package webauthncose

import (
	"crypto"
	"fmt"
)

// AKPPublicKeyData is a credential public key of the AKP (Algorithm Key Pair) key type, which carries its key
// material as an opaque byte string whose interpretation is left entirely to the algorithm the key names. This
// library uses it for the ML-DSA parameter sets of FIPS 204.
//
// Specification: §6. COSE Key Type AKP (https://www.rfc-editor.org/rfc/rfc9964#section-6)
type AKPPublicKeyData struct {
	PublicKeyData

	// PublicKey is the public key, encoded as the algorithm which the key names defines. For the ML-DSA parameter
	// sets this is the encoding of §5.3 of FIPS 204.
	PublicKey []byte `cbor:"-1,keyasint,omitempty" json:"pub"`
}

// Verify an Algorithm Key Pair (AKP) Public Key Signature.
func (k *AKPPublicKeyData) Verify(data []byte, sig []byte) (bool, error) {
	if err := validateAKPPublicKey(k); err != nil {
		return false, err
	}

	return mldsaVerify(COSEAlgorithmIdentifier(k.Algorithm), k.PublicKey, data, sig)
}

// ToPublicKey converts the AKPPublicKeyData to the standard library key of the algorithm it names, which for the
// ML-DSA parameter sets is a *[crypto/mldsa.PublicKey].
//
// The concrete type is not named in the signature because the package which declares it is only present from Go
// 1.27, which is also the point from which this returns a key at all.
func (k *AKPPublicKeyData) ToPublicKey() (key crypto.PublicKey, err error) {
	if err = validateAKPPublicKey(k); err != nil {
		return nil, err
	}

	return mldsaPublicKey(COSEAlgorithmIdentifier(k.Algorithm), k.PublicKey)
}

// validateAKPPublicKey checks that a credential public key of type AKP names an algorithm this library verifies
// with, and carries key material that algorithm accepts.
//
// Specification: §6. COSE Key Type AKP (https://www.rfc-editor.org/rfc/rfc9964#section-6)
func validateAKPPublicKey(k *AKPPublicKeyData) error {
	alg := COSEAlgorithmIdentifier(k.Algorithm)

	switch alg {
	case AlgMLDSA44, AlgMLDSA65, AlgMLDSA87:
		// Every parameter set of FIPS 204, which are the only algorithms registered for this key type.
	default:
		return ErrUnsupportedAlgorithm.WithDetails(fmt.Sprintf("AKP key has unsupported algorithm %s", alg))
	}

	size, ok := mldsaPublicKeySize(alg)
	if !ok {
		return ErrUnsupportedAlgorithm.WithDetails(fmt.Sprintf("AKP key with algorithm %s requires this library to be built with Go 1.27 or newer", alg))
	}

	if len(k.PublicKey) != size {
		return ErrUnsupportedKey.WithDetails(fmt.Sprintf("AKP key with algorithm %s has invalid public key length %d, expected %d", alg, len(k.PublicKey), size))
	}

	if _, err := mldsaPublicKey(alg, k.PublicKey); err != nil {
		return err
	}

	return nil
}
