//go:build !go1.27

package webauthncose

import "crypto"

// mldsaVerify reports that ML-DSA is unavailable.
func mldsaVerify(_ COSEAlgorithmIdentifier, _, _, _ []byte) (valid bool, err error) {
	return false, ErrUnsupportedAlgorithm
}

// mldsaPublicKey reports that ML-DSA is unavailable.
func mldsaPublicKey(_ COSEAlgorithmIdentifier, _ []byte) (key crypto.PublicKey, err error) {
	return nil, ErrUnsupportedAlgorithm
}

// mldsaMarshalPublicKey reports that ML-DSA is unavailable.
func mldsaMarshalPublicKey(_ COSEAlgorithmIdentifier, _ []byte) (der []byte, err error) {
	return nil, ErrUnsupportedAlgorithm
}

// mldsaPublicKeySize reports that no ML-DSA parameter set is available.
func mldsaPublicKeySize(_ COSEAlgorithmIdentifier) (size int, ok bool) {
	return 0, false
}
