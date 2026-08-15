package webauthncose

import (
	"math/big"

	"github.com/go-webauthn/x/crypto/secp256k1"
	secp256k1ecdsa "github.com/go-webauthn/x/crypto/secp256k1/ecdsa"
	"github.com/go-webauthn/x/encoding/asn1"
)

// oidPublicKeyECDSA is the id-ecPublicKey object identifier which names the subject public key algorithm of an
// elliptic curve key.
//
// Specification: §2.1.1 (https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1)
var oidPublicKeyECDSA = asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}

// oidNamedCurveSecp256k1 is the object identifier the SECG assigns to the secp256k1 curve. The standard library
// knows the identifiers of the NIST curves alone, so a key on this curve has to be encoded here.
//
// Specification: §A.2 (https://www.secg.org/sec2-v2.pdf)
var oidNamedCurveSecp256k1 = asn1.ObjectIdentifier{1, 3, 132, 0, 10}

// pkixPublicKey is the SubjectPublicKeyInfo structure a PEM encoded public key carries.
//
// Specification: §4.1 (https://www.rfc-editor.org/rfc/rfc5280#section-4.1)
type pkixPublicKey struct {
	Algorithm pkixAlgorithmIdentifier
	PublicKey asn1.BitString
}

// pkixAlgorithmIdentifier names the subject public key algorithm and, for an elliptic curve key, the curve the key
// belongs to.
//
// Specification: §2.1.1 (https://www.rfc-editor.org/rfc/rfc5480#section-2.1.1)
type pkixAlgorithmIdentifier struct {
	Algorithm  asn1.ObjectIdentifier
	Parameters asn1.ObjectIdentifier
}

// marshalSecp256k1PublicKey encodes a secp256k1 credential public key as a SubjectPublicKeyInfo, mirroring what
// [x509.MarshalPKIXPublicKey] produces for the curves it recognizes. It is the counterpart of
// [marshalEd25519PublicKey] and exists for the same reason: the display helper has nothing else to hand to the PEM
// encoder.
func marshalSecp256k1PublicKey(k *EC2PublicKeyData) ([]byte, error) {
	point := secp256k1PointUncompressed(k)

	return asn1.Marshal(pkixPublicKey{
		Algorithm: pkixAlgorithmIdentifier{
			Algorithm:  oidPublicKeyECDSA,
			Parameters: oidNamedCurveSecp256k1,
		},
		PublicKey: asn1.BitString{Bytes: point, BitLength: len(point) * 8},
	})
}

// verifySecp256k1 verifies an ECDSA signature over the secp256k1 curve, given the digest the signature covers and
// the two integers decoded from its encoding.
//
// The signature is verified by the specialized secp256k1 implementation rather than through [ecdsa.Verify]: the
// standard library does not implement this curve, so it would fall back to its deprecated generic big.Int
// arithmetic, which is neither constant time nor guaranteed to remain available.
func verifySecp256k1(k *EC2PublicKeyData, digest []byte, r, s *big.Int) (valid bool, err error) {
	var public *secp256k1.PublicKey

	if public, err = secp256k1.ParsePubKey(secp256k1PointUncompressed(k)); err != nil {
		return false, ErrUnsupportedKey.WithDetails("EC2 key is not a valid secp256k1 public key")
	}

	// ECDSA defines both integers over the interval [1, n-1]. A signature which falls outside it is rejected here
	// as the scalar type below reduces rather than reports a value it cannot represent, and a negative integer
	// loses its sign entirely when its magnitude is taken.
	if r.Sign() <= 0 || s.Sign() <= 0 {
		return false, ErrSigNotProvidedOrInvalid
	}

	var sr, ss secp256k1.ModNScalar

	if sr.SetByteSlice(r.Bytes()) || ss.SetByteSlice(s.Bytes()) {
		return false, ErrSigNotProvidedOrInvalid
	}

	return secp256k1ecdsa.NewSignature(&sr, &ss).Verify(digest, public), nil
}

// secp256k1PointUncompressed serializes the point a credential public key carries in the uncompressed form of
// §2.3.3, which is the form both the parser and the encoder above expect.
//
// Specification: §2.3.3 (https://www.secg.org/sec1-v2.pdf)
func secp256k1PointUncompressed(k *EC2PublicKeyData) []byte {
	point := make([]byte, 0, 1+len(k.XCoord)+len(k.YCoord))

	point = append(point, secp256k1.PubKeyFormatUncompressed)
	point = append(point, k.XCoord...)
	point = append(point, k.YCoord...)

	return point
}
