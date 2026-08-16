//go:build !go1.27

package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// TestAKPHelpersUnsupported asserts that neither helper claims a key on a build which cannot verify an ML-DSA
// signature. Neither is reached today, as no parser on such a build produces a key of the AKP key type, so they are
// asserted directly: they are what keeps the attestation formats from treating an unverifiable key as one they
// handle if that ever changes.
func TestAKPHelpersUnsupported(t *testing.T) {
	keys := []any{
		struct{}{},
		webauthncose.EC2PublicKeyData{},
		webauthncose.RSAPublicKeyData{},
		webauthncose.OKPPublicKeyData{},
	}

	for _, key := range keys {
		algorithm, ok := akpKeyAlgorithm(key)

		assert.False(t, ok)
		assert.Zero(t, algorithm)

		public, ok, err := akpPublicKey(key)

		assert.False(t, ok)
		assert.Nil(t, public)
		require.NoError(t, err)
	}
}
