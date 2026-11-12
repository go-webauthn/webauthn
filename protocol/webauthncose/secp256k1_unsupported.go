//go:build webauthn_no_es256k

package webauthncose

import (
	"crypto/elliptic"
	"math/big"
)

// This file supplies the secp256k1 arms which [ParsePublicKey], [DisplayPublicKey] and [EC2PublicKeyData.Verify]
// delegate ES256K to on a build with the webauthn_no_es256k tag.
//
// The tag omits the secp256k1 implementation, and the precomputed tables it carries, from the binary of a Relying
// Party which does not request ES256K. No curve is resolved for the algorithm, so the credential is refused as an
// unsupported algorithm when it is parsed and none of the remaining arms is reached.

// secp256k1Curve resolves no curve, which refuses the algorithm wherever a curve is required.
func secp256k1Curve() elliptic.Curve {
	return nil
}

// validateSecp256k1PublicKey refuses an ES256K key, which no parser on this build accepts.
func validateSecp256k1PublicKey(_ *EC2PublicKeyData) error {
	return ErrUnsupportedAlgorithm
}

// marshalSecp256k1PublicKey refuses an ES256K key, which no parser on this build accepts.
func marshalSecp256k1PublicKey(_ *EC2PublicKeyData) ([]byte, error) {
	return nil, ErrUnsupportedAlgorithm
}

// verifySecp256k1 refuses an ES256K key, which no parser on this build accepts.
func verifySecp256k1(_ *EC2PublicKeyData, _ []byte, _, _ *big.Int) (bool, error) {
	return false, ErrUnsupportedAlgorithm
}
