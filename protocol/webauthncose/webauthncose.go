package webauthncose

import (
	"bytes"
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"hash"
	"math"
	"math/big"

	"github.com/google/go-tpm/tpm2"

	"github.com/go-webauthn/x/crypto/secp256k1"
	"github.com/go-webauthn/x/encoding/asn1"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// PublicKeyData The public key portion of a Relying Party-specific credential key pair, generated
// by an authenticator and returned to a Relying Party at registration time. We unpack this object
// using fxamacker's cbor library ("github.com/fxamacker/cbor/v2") which is why there are cbor tags
// included. The tag field values correspond to the IANA COSE keys that give their respective
// values.
//
// Specification: §6.4.1.1. Examples of credentialPublicKey Values Encoded in COSE_Key Format (https://www.w3.org/TR/webauthn/#sctn-encoded-credPubKey-examples)
type PublicKeyData struct {
	// Decode the results to int by default.
	_struct bool `cbor:",keyasint" json:"public_key"` //nolint:govet,staticcheck

	// The type of key created. Should be OKP, EC2, or RSA.
	KeyType int64 `cbor:"1,keyasint" json:"kty"`

	// A COSEAlgorithmIdentifier for the algorithm used to derive the key signature.
	Algorithm int64 `cbor:"3,keyasint" json:"alg"`
}

type EC2PublicKeyData struct {
	PublicKeyData

	// If the key type is EC2, the curve on which we derive the signature from.
	Curve int64 `cbor:"-1,keyasint,omitempty" json:"crv"`

	// A byte string 32 bytes in length that holds the x coordinate of the key.
	XCoord []byte `cbor:"-2,keyasint,omitempty" json:"x"`

	// A byte string 32 bytes in length that holds the y coordinate of the key.
	YCoord []byte `cbor:"-3,keyasint,omitempty" json:"y"`
}

type RSAPublicKeyData struct {
	PublicKeyData

	// Represents the modulus parameter for the RSA algorithm.
	Modulus []byte `cbor:"-1,keyasint,omitempty" json:"n"`

	// Represents the exponent parameter for the RSA algorithm.
	Exponent []byte `cbor:"-2,keyasint,omitempty" json:"e"`
}

type OKPPublicKeyData struct {
	PublicKeyData

	// The curve the key is on. §5.8.5 requires a key with algorithm -8 (EdDSA) to specify 6 (Ed25519) here.
	Curve int64 `cbor:"-1,keyasint,omitempty" json:"crv"`

	// A byte string that holds the x coordinate of the key.
	XCoord []byte `cbor:"-2,keyasint,omitempty" json:"x"`
}

// Verify Octet Key Pair (OKP) Public Key Signature.
func (k *OKPPublicKeyData) Verify(data []byte, sig []byte) (bool, error) {
	if err := validateOKPPublicKey(k); err != nil {
		return false, err
	}

	var key ed25519.PublicKey = make([]byte, ed25519.PublicKeySize)

	copy(key, k.XCoord)

	return ed25519.Verify(key, data, sig), nil
}

// Verify Elliptic Curve Public Key Signature.
func (k *EC2PublicKeyData) Verify(data []byte, sig []byte) (valid bool, err error) {
	if err = validateEC2PublicKey(k); err != nil {
		return false, err
	}

	// validateEC2PublicKey has already rejected an algorithm with no curve, and every algorithm which survives that
	// has a hash registered, so this cannot fail as the two are written today. It is checked rather than discarded
	// so that widening one of the two without the other is an error instead of a silent substitution.
	h, ok := HasherFromCOSEAlg(COSEAlgorithmIdentifier(k.Algorithm))
	if !ok {
		return false, ErrUnsupportedAlgorithm.WithDetails(fmt.Sprintf("EC2 key algorithm %s has no registered hash", COSEAlgorithmIdentifier(k.Algorithm)))
	}

	h.Write(data)

	e := &ECDSASignature{}

	if _, err = asn1.Unmarshal(sig, e); err != nil {
		return false, ErrSigNotProvidedOrInvalid
	}

	// DER is a canonical encoding, so re-encoding the decoded integers reproduces a conforming signature exactly.
	// Anything else is rejected: data trailing the signature and elements trailing the two integers within it are
	// both discarded by the decoder rather than reported, and an integer which is not minimally encoded decodes to
	// the same value as the one which is. A Relying Party which accepts a non-conforming encoding normalizes the
	// signature before it reaches this point rather than relaxing the check here.
	var der []byte

	if der, err = asn1.Marshal(*e); err != nil || !bytes.Equal(der, sig) {
		return false, ErrSigNotProvidedOrInvalid
	}

	digest := h.Sum(nil)

	// secp256k1 is verified by a dedicated implementation, reached only once the signature has satisfied the same
	// encoding requirements as every other curve.
	if COSEAlgorithmIdentifier(k.Algorithm) == AlgES256K {
		return verifySecp256k1(k, digest, e.R, e.S)
	}

	pubkey := &ecdsa.PublicKey{
		Curve: ec2AlgCurve(k.Algorithm),
		X:     big.NewInt(0).SetBytes(k.XCoord),
		Y:     big.NewInt(0).SetBytes(k.YCoord),
	}

	return ecdsa.Verify(pubkey, digest, e.R, e.S), nil
}

// ToECDSA converts the EC2PublicKeyData to an ecdsa.PublicKey.
func (k *EC2PublicKeyData) ToECDSA() (key *ecdsa.PublicKey, err error) {
	if err = validateEC2PublicKey(k); err != nil {
		return nil, err
	}

	return &ecdsa.PublicKey{
		Curve: ec2AlgCurve(k.Algorithm),
		X:     big.NewInt(0).SetBytes(k.XCoord),
		Y:     big.NewInt(0).SetBytes(k.YCoord),
	}, nil
}

// Verify RSA Public Key Signature.
func (k *RSAPublicKeyData) Verify(data []byte, sig []byte) (valid bool, err error) {
	var e int

	if e, err = validateRSAPublicKey(k); err != nil {
		return false, err
	}

	pubkey := &rsa.PublicKey{
		N: big.NewInt(0).SetBytes(k.Modulus),
		E: e,
	}

	coseAlg := COSEAlgorithmIdentifier(k.Algorithm)

	algDetail, ok := COSESignatureAlgorithmDetails[coseAlg]
	if !ok {
		return false, ErrUnsupportedAlgorithm
	}

	hash := algDetail.hash
	h := hash.New()
	h.Write(data)

	switch coseAlg {
	case AlgPS256, AlgPS384, AlgPS512:
		err = rsa.VerifyPSS(pubkey, hash, h.Sum(nil), sig, nil)

		return err == nil, err
	case AlgRS1, AlgRS256, AlgRS384, AlgRS512:
		err = rsa.VerifyPKCS1v15(pubkey, hash, h.Sum(nil), sig)

		return err == nil, err
	default:
		return false, ErrUnsupportedAlgorithm
	}
}

// ParsePublicKey figures out what kind of COSE material was provided and create the data for the new key.
func ParsePublicKey(keyBytes []byte) (publicKey any, err error) {
	pk := PublicKeyData{}

	if err = webauthncbor.Unmarshal(keyBytes, &pk); err != nil {
		return nil, ErrUnsupportedKey
	}

	switch COSEKeyType(pk.KeyType) {
	case OctetKey:
		var o OKPPublicKeyData

		if err = webauthncbor.Unmarshal(keyBytes, &o); err != nil {
			return nil, err
		}

		o.PublicKeyData = pk

		if err = validateOKPPublicKey(&o); err != nil {
			return nil, err
		}

		return o, nil
	case EllipticKey:
		var e EC2PublicKeyData

		if err = webauthncbor.Unmarshal(keyBytes, &e); err != nil {
			return nil, err
		}

		e.PublicKeyData = pk

		if err = validateEC2PublicKey(&e); err != nil {
			return nil, err
		}

		return e, nil
	case RSAKey:
		var r RSAPublicKeyData

		if err = webauthncbor.Unmarshal(keyBytes, &r); err != nil {
			return nil, err
		}

		r.PublicKeyData = pk

		if _, err = validateRSAPublicKey(&r); err != nil {
			return nil, err
		}

		return r, nil
	case AKP:
		return parseAKPPublicKey(pk, keyBytes)
	default:
		return nil, ErrUnsupportedKey
	}
}

// ParseFIDOPublicKey is only used when the appID extension is configured by the assertion response.
func ParseFIDOPublicKey(keyBytes []byte) (data EC2PublicKeyData, err error) {
	key, err := ecdh.P256().NewPublicKey(keyBytes)
	if err != nil {
		return data, fmt.Errorf("failed to parse FIDO public key: %w", err)
	}

	// Raw bytes for an uncompressed P-256 point: 0x04 || x(32) || y(32).
	raw := key.Bytes()

	return EC2PublicKeyData{
		PublicKeyData: PublicKeyData{
			KeyType:   int64(EllipticKey),
			Algorithm: int64(AlgES256),
		},
		Curve:  int64(P256),
		XCoord: raw[1 : 1+ecCoordSize],
		YCoord: raw[1+ecCoordSize:],
	}, nil
}

func VerifySignature(key any, data []byte, sig []byte) (bool, error) {
	switch k := key.(type) {
	case OKPPublicKeyData:
		return k.Verify(data, sig)
	case EC2PublicKeyData:
		return k.Verify(data, sig)
	case RSAPublicKeyData:
		return k.Verify(data, sig)
	default:
		return verifyAKPSignature(key, data, sig)
	}
}

func DisplayPublicKey(cpk []byte) string {
	parsedKey, err := ParsePublicKey(cpk)
	if err != nil {
		return keyCannotDisplay
	}

	var data []byte

	switch k := parsedKey.(type) {
	case RSAPublicKeyData:
		var e int

		if e, err = ParseRSAPublicKeyDataExponent(&k); err != nil {
			return keyCannotDisplay
		}

		rKey := &rsa.PublicKey{
			N: big.NewInt(0).SetBytes(k.Modulus),
			E: e,
		}

		if data, err = x509.MarshalPKIXPublicKey(rKey); err != nil {
			return keyCannotDisplay
		}
	case EC2PublicKeyData:
		curve := ec2AlgCurve(k.Algorithm)
		if curve == nil {
			return keyCannotDisplay
		}

		// The standard library has no object identifier for secp256k1 and refuses to marshal a key on it.
		if COSEAlgorithmIdentifier(k.Algorithm) == AlgES256K {
			if data, err = marshalSecp256k1PublicKey(&k); err != nil {
				return keyCannotDisplay
			}

			break
		}

		eKey := &ecdsa.PublicKey{
			Curve: curve,
			X:     big.NewInt(0).SetBytes(k.XCoord),
			Y:     big.NewInt(0).SetBytes(k.YCoord),
		}

		if data, err = x509.MarshalPKIXPublicKey(eKey); err != nil {
			return keyCannotDisplay
		}
	case OKPPublicKeyData:
		if len(k.XCoord) != ed25519.PublicKeySize {
			return keyCannotDisplay
		}

		var oKey ed25519.PublicKey = make([]byte, ed25519.PublicKeySize)

		copy(oKey, k.XCoord)

		if data, err = marshalEd25519PublicKey(oKey); err != nil {
			return keyCannotDisplay
		}
	default:
		if data, err = displayAKPPublicKey(parsedKey); err != nil {
			return keyCannotDisplay
		}

		// A nil encoding without an error is a key type which is not rendered here at all, as distinct from an
		// AKP key whose material could not be encoded.
		if data == nil {
			return "Cannot display key of this type"
		}
	}

	pemBytes := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: data,
	})

	return string(pemBytes)
}

func (k *EC2PublicKeyData) TPMCurveID() tpm2.TPMECCCurve {
	switch COSEEllipticCurve(k.Curve) {
	case P256:
		return tpm2.TPMECCNistP256 // TPM_ECC_NIST_P256.
	case P384:
		return tpm2.TPMECCNistP384 // TPM_ECC_NIST_P384.
	case P521:
		return tpm2.TPMECCNistP521 // TPM_ECC_NIST_P521.
	default:
		return tpm2.TPMECCNone // TPM_ECC_NONE.
	}
}

func ec2AlgCurve(coseAlg int64) elliptic.Curve {
	switch COSEAlgorithmIdentifier(coseAlg) {
	case AlgES512, AlgESP512:
		return elliptic.P521()
	case AlgES384, AlgESP384:
		return elliptic.P384()
	case AlgES256, AlgESP256:
		return elliptic.P256()
	case AlgES256K:
		// The adaptor is returned so a secp256k1 key is measured and represented like any other, but neither the
		// point check nor the signature verification goes through this interface: both use the specialized
		// implementation instead. See [validateEC2PublicKey] and [verifySecp256k1].
		return secp256k1.S256() //nolint:staticcheck // The adaptor supplies the curve parameters and nothing else.
	default:
		return nil
	}
}

// SigAlgFromCOSEAlg return which signature algorithm is being used from the COSE Key.
func SigAlgFromCOSEAlg(coseAlg COSEAlgorithmIdentifier) x509.SignatureAlgorithm {
	d, ok := COSESignatureAlgorithmDetails[coseAlg]
	if !ok {
		return x509.UnknownSignatureAlgorithm
	}

	return d.sigAlg
}

// HasherFromCOSEAlg returns the hashing interface to be used for a given COSE algorithm, and whether this library
// has one registered for it. An unregistered algorithm yields no hash rather than a substituted one, so a caller
// which reaches this with an algorithm it has not itself constrained cannot hash with an algorithm the credential
// never named.
//
// An algorithm which signs the message itself rather than a digest of it, such as ML-DSA, registers no hash and is
// reported the same way. The availability of the registered hash is what decides this rather than its presence, as
// constructing an unavailable hash panics.
func HasherFromCOSEAlg(coseAlg COSEAlgorithmIdentifier) (hash.Hash, bool) {
	d, ok := COSESignatureAlgorithmDetails[coseAlg]
	if !ok || !d.hash.Available() {
		return nil, false
	}

	return d.hash.New(), true
}

// coseAlgorithmCurve describes the elliptic curve a credential public key using a particular algorithm names.
type coseAlgorithmCurve struct {
	// curve is the curve §5.8.5 binds to the algorithm.
	curve COSEEllipticCurve

	// required records whether the specification requires the crv parameter to be present at all.
	required bool
}

// validateKeyCurve checks the curve a credential public key names against the one §5.8.5 binds to its algorithm. The
// keyType names the COSE key type in the error so a failure identifies which of the two key structures produced it.
//
// An algorithm this map does not cover is not rejected here: the callers reject an algorithm they cannot verify with
// on their own, and an algorithm which names no curve has nothing to check.
//
// Specification: §5.8.5. Cryptographic Algorithm Identifier (https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier)
func validateKeyCurve(keyType string, algorithm, curve int64) error {
	alg := COSEAlgorithmIdentifier(algorithm)

	expected, ok := coseAlgorithmCurves[alg]
	if !ok {
		return nil
	}

	crv := COSEEllipticCurve(curve)

	if crv == expected.curve {
		return nil
	}

	// The zero value is the reserved curve identifier, which is how an absent crv parameter decodes.
	if crv == EllipticCurveReserved && !expected.required {
		return nil
	}

	specified := "curve " + crv.String()

	if crv == EllipticCurveReserved {
		specified = "no curve"
	}

	return ErrUnsupportedKey.WithDetails(fmt.Sprintf("%s key with algorithm %s must specify curve %s but it specified %s", keyType, alg, expected.curve, specified))
}

func validateOKPPublicKey(k *OKPPublicKeyData) error {
	// The algorithm is gated before anything else, as [validateEC2PublicKey] gates its own. Without this an OKP key
	// naming any algorithm at all is accepted and then verified with Ed25519 regardless of what it named, since
	// Ed25519 is the only OKP curve implemented. It also keeps an OKP key out of the case [validateKeyCurve] passes
	// over, because every algorithm accepted here is one that map covers.
	switch alg := COSEAlgorithmIdentifier(k.Algorithm); alg {
	case AlgEdDSA, AlgEd25519:
		// Both name the Ed25519 curve, the generic identifier by way of the crv parameter the next check enforces.
	default:
		return ErrUnsupportedAlgorithm.WithDetails(fmt.Sprintf("OKP key has unsupported algorithm %s", alg))
	}

	// The curve is checked before the key material so that both key structures report what the key declares about
	// itself before what it carries.
	if err := validateKeyCurve("OKP", k.Algorithm, k.Curve); err != nil {
		return err
	}

	if len(k.XCoord) != ed25519.PublicKeySize {
		return ErrUnsupportedKey.WithDetails(fmt.Sprintf("OKP key x coordinate has invalid length %d, expected %d", len(k.XCoord), ed25519.PublicKeySize))
	}

	return nil
}

func validateEC2PublicKey(k *EC2PublicKeyData) error {
	curve := ec2AlgCurve(k.Algorithm)
	if curve == nil {
		return ErrUnsupportedAlgorithm.WithDetails("Unsupported EC2 algorithm")
	}

	if err := validateKeyCurve("EC2", k.Algorithm, k.Curve); err != nil {
		return err
	}

	byteLen := (curve.Params().BitSize + 7) / 8

	if len(k.XCoord) != byteLen || len(k.YCoord) != byteLen {
		return ErrUnsupportedKey.WithDetails("EC2 key x or y coordinate has invalid length")
	}

	// A secp256k1 point is checked by the same parser which verification uses, so the two agree on what a valid
	// key is. It additionally rejects a coordinate which is not reduced modulo the field prime, where the generic
	// curve reduces it and reports the resulting point as valid.
	if COSEAlgorithmIdentifier(k.Algorithm) == AlgES256K {
		if _, err := secp256k1.ParsePubKey(secp256k1PointUncompressed(k)); err != nil {
			return ErrUnsupportedKey.WithDetails("EC2 key point is not on curve")
		}

		return nil
	}

	x := new(big.Int).SetBytes(k.XCoord)
	y := new(big.Int).SetBytes(k.YCoord)

	if !curve.IsOnCurve(x, y) {
		return ErrUnsupportedKey.WithDetails("EC2 key point is not on curve")
	}

	return nil
}

func validateRSAPublicKey(k *RSAPublicKeyData) (e int, err error) {
	n := new(big.Int).SetBytes(k.Modulus)
	if n.Sign() <= 0 {
		return e, ErrUnsupportedKey.WithDetails("RSA key contains zero or empty modulus")
	}

	if e, err = ParseRSAPublicKeyDataExponent(k); err != nil {
		return e, ErrUnsupportedKey.WithDetails(fmt.Sprintf("RSA key contains invalid exponent: %v", err))
	}

	return e, nil
}

// ParseRSAPublicKeyDataExponent safely parses the exponent value of the provided RSAPublicKeyData.
func ParseRSAPublicKeyDataExponent(k *RSAPublicKeyData) (exp int, err error) {
	if k == nil {
		return 0, fmt.Errorf("invalid key")
	}

	if len(k.Exponent) == 0 {
		return 0, fmt.Errorf("invalid exponent length")
	}

	for _, b := range k.Exponent {
		if exp > (math.MaxInt >> 8) {
			return 0, ErrUnsupportedKey
		}

		exp = (exp << 8) | int(b)
	}

	if exp <= 0 {
		return 0, ErrUnsupportedKey
	}

	return exp, nil
}
