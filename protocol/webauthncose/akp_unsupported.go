//go:build !go1.27

package webauthncose

// This file supplies the arms which [ParsePublicKey], [VerifySignature] and [DisplayPublicKey] delegate the AKP key
// type to on a build which cannot verify a signature made with one.
//
// The only algorithms registered for that key type are the ML-DSA parameter sets, which this library verifies with
// through crypto/mldsa, and the standard library did not have that package before Go 1.27. The credential is
// refused when it is parsed rather than when it is verified, so a Relying Party never registers a credential it
// would be unable to authenticate with.

// parseAKPPublicKey refuses a credential public key of the AKP key type.
func parseAKPPublicKey(_ PublicKeyData, _ []byte) (key any, err error) {
	return nil, ErrUnsupportedKey.WithDetails("AKP key type requires this library to be built with Go 1.27 or newer")
}

// verifyAKPSignature refuses a key of the AKP key type, which no parser on this build produces.
func verifyAKPSignature(_ any, _ []byte, _ []byte) (bool, error) {
	return false, ErrUnsupportedKey
}

// displayAKPPublicKey reports that the key is not one it renders, as no key of the AKP key type reaches it.
func displayAKPPublicKey(_ any) (der []byte, err error) {
	return nil, nil
}
