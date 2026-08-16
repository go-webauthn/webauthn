//go:build !go1.27

package protocol

import (
	"crypto"
)

// akpKeyAlgorithm reports that the key is not one of the AKP key type. No parser on a build which cannot verify an
// ML-DSA signature produces such a key, so nothing carrying one reaches the attestation formats.
func akpKeyAlgorithm(_ any) (algorithm int64, ok bool) {
	return 0, false
}

// akpPublicKey reports that the key is not one of the AKP key type, for the same reason as [akpKeyAlgorithm].
func akpPublicKey(_ any) (public crypto.PublicKey, ok bool, err error) {
	return nil, false, nil
}
