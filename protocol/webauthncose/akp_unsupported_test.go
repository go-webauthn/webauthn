//go:build !go1.27

package webauthncose

import (
	"crypto/x509"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestParsePublicKeyAKPUnsupported(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			parsed, err := ParsePublicKey(akpTestKey(t, tc.alg, tc.publicKeySize))

			assert.Nil(t, parsed)
			require.EqualError(t, err, "AKP key with algorithm "+tc.alg.String()+" requires this library to be built with Go 1.27 or newer")
		})
	}
}

func TestAKPPublicKeyDataVerifyUnsupported(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			key := AKPPublicKeyData{
				PublicKeyData: PublicKeyData{
					KeyType:   int64(AKP),
					Algorithm: int64(tc.alg),
				},
				PublicKey: make([]byte, tc.publicKeySize),
			}

			valid, err := key.Verify([]byte("data to sign"), []byte("signature"))

			assert.False(t, valid)
			require.EqualError(t, err, "AKP key with algorithm "+tc.alg.String()+" requires this library to be built with Go 1.27 or newer")
		})
	}
}

func TestMLDSAAlgorithmDetailsUnsupported(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			assert.Equal(t, x509.UnknownSignatureAlgorithm, SigAlgFromCOSEAlg(tc.alg))

			h, ok := HasherFromCOSEAlg(tc.alg)

			assert.Nil(t, h)
			assert.False(t, ok)
		})
	}
}

func TestDisplayPublicKeyAKPUnsupported(t *testing.T) {
	assert.Equal(t, keyCannotDisplay, DisplayPublicKey(akpTestKey(t, AlgMLDSA44, 1312)))
}

func TestAKPPublicKeyDataToPublicKeyUnsupported(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			key := AKPPublicKeyData{
				PublicKeyData: PublicKeyData{
					KeyType:   int64(AKP),
					Algorithm: int64(tc.alg),
				},
				PublicKey: make([]byte, tc.publicKeySize),
			}

			public, err := key.ToPublicKey()

			assert.Nil(t, public)
			require.EqualError(t, err, "AKP key with algorithm "+tc.alg.String()+" requires this library to be built with Go 1.27 or newer")
		})
	}
}

func TestParsePublicKeyAKPRejectsAlgorithmWhichIsNotMLDSA(t *testing.T) {
	parsed, err := ParsePublicKey(akpTestKey(t, AlgES256, 1312))

	assert.Nil(t, parsed)
	require.EqualError(t, err, "AKP key has unsupported algorithm ES256")
}

func TestMLDSAFailsClosedUnsupported(t *testing.T) {
	pub, data, sig := make([]byte, 1312), []byte("data to sign"), make([]byte, 2420)

	t.Run("PublicKeySize", func(t *testing.T) {
		size, ok := mldsaPublicKeySize(AlgMLDSA44)

		assert.False(t, ok)
		assert.Zero(t, size)
	})

	t.Run("Verify", func(t *testing.T) {
		valid, err := mldsaVerify(AlgMLDSA44, pub, data, sig)

		assert.False(t, valid)
		require.EqualError(t, err, "Unsupported public key algorithm")
	})

	t.Run("PublicKey", func(t *testing.T) {
		public, err := mldsaPublicKey(AlgMLDSA44, pub)

		assert.Nil(t, public)
		require.EqualError(t, err, "Unsupported public key algorithm")
	})

	t.Run("MarshalPublicKey", func(t *testing.T) {
		der, err := mldsaMarshalPublicKey(AlgMLDSA44, pub)

		assert.Nil(t, der)
		require.EqualError(t, err, "Unsupported public key algorithm")
	})
}

var akpTestAlgorithms = []struct {
	alg           COSEAlgorithmIdentifier
	publicKeySize int
}{
	{AlgMLDSA44, 1312},
	{AlgMLDSA65, 1952},
	{AlgMLDSA87, 2592},
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
