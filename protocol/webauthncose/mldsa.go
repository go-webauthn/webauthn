//go:build go1.27

package webauthncose

import (
	"crypto/mldsa"
	"crypto/x509"
)

// mldsaVerify verifies a pure ML-DSA signature made by the key material an AKP credential public key carries.
//
// Specification: §5. ML-DSA (https://www.rfc-editor.org/rfc/rfc9964#section-5)
func mldsaVerify(alg COSEAlgorithmIdentifier, pub, data, sig []byte) (valid bool, err error) {
	params, ok := mldsaParameters(alg)
	if !ok {
		return false, ErrUnsupportedAlgorithm
	}

	var key *mldsa.PublicKey

	if key, err = mldsa.NewPublicKey(params, pub); err != nil {
		return false, ErrUnsupportedKey.WithDetails("AKP key is not a valid ML-DSA public key")
	}

	if err = mldsa.Verify(key, data, sig, nil); err != nil {
		return false, nil
	}

	return true, nil
}

// mldsaPublicKey parses the key material an AKP credential public key carries into the standard library key of the
// parameter set its algorithm names.
func mldsaPublicKey(alg COSEAlgorithmIdentifier, pub []byte) (key *mldsa.PublicKey, err error) {
	params, ok := mldsaParameters(alg)
	if !ok {
		return nil, ErrUnsupportedAlgorithm
	}

	if key, err = mldsa.NewPublicKey(params, pub); err != nil {
		return nil, ErrUnsupportedKey.WithDetails("AKP key is not a valid ML-DSA public key")
	}

	return key, nil
}

// mldsaMarshalPublicKey encodes the key material an AKP credential public key carries as a SubjectPublicKeyInfo,
// which is what the display helper hands to the PEM encoder.
func mldsaMarshalPublicKey(alg COSEAlgorithmIdentifier, pub []byte) (der []byte, err error) {
	var key *mldsa.PublicKey

	if key, err = mldsaPublicKey(alg, pub); err != nil {
		return nil, err
	}

	return x509.MarshalPKIXPublicKey(key)
}

// mldsaPublicKeySize returns the length FIPS 204 fixes for the public key of the parameter set an ML-DSA algorithm
// identifier names, and whether this build can verify with it at all.
func mldsaPublicKeySize(alg COSEAlgorithmIdentifier) (size int, ok bool) {
	params, ok := mldsaParameters(alg)
	if !ok {
		return 0, false
	}

	return params.PublicKeySize(), true
}

// mldsaParameters returns the FIPS 204 parameter set which an ML-DSA algorithm identifier names.
func mldsaParameters(alg COSEAlgorithmIdentifier) (params mldsa.Parameters, ok bool) {
	switch alg {
	case AlgMLDSA44:
		return mldsa.MLDSA44(), true
	case AlgMLDSA65:
		return mldsa.MLDSA65(), true
	case AlgMLDSA87:
		return mldsa.MLDSA87(), true
	default:
		return params, false
	}
}
