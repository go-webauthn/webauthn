//go:build !go1.27

package webauthncose

import (
	"crypto/x509"
	"strconv"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// akpTestAlgorithms is every ML-DSA parameter set, named by its raw identifier because a build which cannot verify
// with them does not declare a constant for any of them.
var akpTestAlgorithms = []struct {
	alg           COSEAlgorithmIdentifier
	publicKeySize int
}{
	{-48, 1312},
	{-49, 1952},
	{-50, 2592},
}

// TestParsePublicKeyAKPUnsupported asserts that a build which cannot verify an ML-DSA signature rejects a
// credential public key of the AKP key type when it is parsed.
//
// The rejection has to happen here rather than at verification time. A Relying Party which accepted the credential
// at registration would have stored one it can never authenticate with, and would have no way to tell the user why
// their authenticator stopped working.
func TestParsePublicKeyAKPUnsupported(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			parsed, err := ParsePublicKey(akpTestKey(t, tc.alg, tc.publicKeySize))

			assert.Nil(t, parsed)
			require.EqualError(t, err, "AKP key type requires this library to be built with Go 1.27 or newer")
		})
	}
}

// TestAKPAlgorithmsUnregisteredUnsupported asserts that the ML-DSA identifiers name nothing on this build, so an
// attestation statement which declares one is refused for want of a signature algorithm rather than verified some
// other way, and no caller is handed a hash for an algorithm which does not pre-hash.
func TestAKPAlgorithmsUnregisteredUnsupported(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			assert.Equal(t, x509.UnknownSignatureAlgorithm, SigAlgFromCOSEAlg(tc.alg))

			h, ok := HasherFromCOSEAlg(tc.alg)

			assert.Nil(t, h)
			assert.False(t, ok)

			// The identifier is not modelled at all, so it renders as its number rather than a name.
			assert.Equal(t, strconv.Itoa(int(tc.alg)), tc.alg.String())
		})
	}
}

// TestVerifySignatureAKPUnsupported asserts that the arm which handles the AKP key type refuses anything reaching
// it, which is the guarantee that a build unable to verify an ML-DSA signature cannot be made to accept one.
func TestVerifySignatureAKPUnsupported(t *testing.T) {
	valid, err := VerifySignature(struct{}{}, []byte("data to sign"), []byte("signature"))

	assert.False(t, valid)
	require.EqualError(t, err, "Unsupported Public Key Type")

	valid, err = verifyAKPSignature(struct{}{}, []byte("data to sign"), []byte("signature"))

	assert.False(t, valid)
	require.EqualError(t, err, "Unsupported Public Key Type")
}

// TestDisplayPublicKeyAKPUnsupported asserts that an AKP key is reported as one which cannot be displayed rather
// than rendered from key material this build cannot interpret.
func TestDisplayPublicKeyAKPUnsupported(t *testing.T) {
	assert.Equal(t, keyCannotDisplay, DisplayPublicKey(akpTestKey(t, -48, 1312)))

	der, err := displayAKPPublicKey(struct{}{})

	assert.Nil(t, der)
	require.NoError(t, err)
}

type akpTestCOSEKey struct {
	_struct   bool   `cbor:",keyasint"` //nolint:unused
	KeyType   int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	PublicKey []byte `cbor:"-1,keyasint"`
}

func akpTestKey(t *testing.T, alg COSEAlgorithmIdentifier, size int) []byte {
	t.Helper()

	encoded, err := webauthncbor.Marshal(akpTestCOSEKey{
		KeyType:   int64(AKP),
		Algorithm: int64(alg),
		PublicKey: make([]byte, size),
	})

	require.NoError(t, err)

	return encoded
}
