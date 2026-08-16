//go:build go1.27

package protocol

import (
	"crypto"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// akpKeyAlgorithm returns the COSE algorithm a credential public key of the AKP key type names, and whether the key
// is one at all. It exists so that the attestation formats can hold such a key to the algorithm an attestation
// statement declares without naming a type which only exists on a build that can verify with it.
func akpKeyAlgorithm(key any) (algorithm int64, ok bool) {
	k, is := key.(webauthncose.AKPPublicKeyData)
	if !is {
		return 0, false
	}

	return k.Algorithm, true
}

// akpPublicKey converts a credential public key of the AKP key type into the equivalent standard library key. The
// second value reports whether the key was one at all, which distinguishes a key this does not handle from an AKP
// key which could not be converted.
func akpPublicKey(key any) (public crypto.PublicKey, ok bool, err error) {
	k, is := key.(webauthncose.AKPPublicKeyData)
	if !is {
		return nil, false, nil
	}

	public, err = k.ToPublicKey()

	return public, true, err
}
