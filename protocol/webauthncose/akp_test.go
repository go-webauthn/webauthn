//go:build go1.27

package webauthncose

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestAKPPublicKeyDataVerify(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			private, encoded := akpTestKey(t, tc.alg)

			parsed, err := ParsePublicKey(encoded)

			require.NoError(t, err)
			require.IsType(t, AKPPublicKeyData{}, parsed)

			key, _ := parsed.(AKPPublicKeyData)

			require.Len(t, key.PublicKey, tc.publicKeySize)

			data := []byte("data to sign")
			sig := akpTestSign(t, private, data)

			require.Len(t, sig, tc.signatureSize)

			valid, err := VerifySignature(parsed, data, sig)

			require.NoError(t, err)
			assert.True(t, valid)

			t.Run("ShouldRejectSignatureOverDifferentData", func(t *testing.T) {
				valid, err := VerifySignature(parsed, []byte("different data"), sig)

				require.NoError(t, err)
				assert.False(t, valid)
			})

			t.Run("ShouldRejectSignatureFromDifferentKey", func(t *testing.T) {
				other, _ := akpTestKey(t, tc.alg)

				valid, err := VerifySignature(parsed, data, akpTestSign(t, other, data))

				require.NoError(t, err)
				assert.False(t, valid)
			})

			t.Run("ShouldRejectTamperedSignature", func(t *testing.T) {
				tampered := make([]byte, len(sig))

				copy(tampered, sig)

				tampered[0] ^= 0xff

				valid, err := VerifySignature(parsed, data, tampered)

				require.NoError(t, err)
				assert.False(t, valid)
			})

			t.Run("ShouldRejectTruncatedSignature", func(t *testing.T) {
				valid, err := VerifySignature(parsed, data, sig[:len(sig)-1])

				require.NoError(t, err)
				assert.False(t, valid)
			})

			t.Run("ShouldRejectEmptySignature", func(t *testing.T) {
				valid, err := VerifySignature(parsed, data, nil)

				require.NoError(t, err)
				assert.False(t, valid)
			})
		})
	}
}

// TestAKPPublicKeyDataVerifyRejectsContextualizedSignature asserts that a signature made under a non-empty context
// string is rejected. RFC 9964 requires the context of every ML-DSA signature it registers to be the empty string,
// and a signature made under any other context is one this library must not accept as though it were made under
// none.
//
// Specification: §5. ML-DSA (https://www.rfc-editor.org/rfc/rfc9964#section-5)
func TestAKPPublicKeyDataVerifyRejectsContextualizedSignature(t *testing.T) {
	private, encoded := akpTestKey(t, AlgMLDSA44)

	parsed, err := ParsePublicKey(encoded)

	require.NoError(t, err)

	data := []byte("data to sign")

	sig, err := private.Sign(nil, data, &mldsa.Options{Context: "webauthn"})

	require.NoError(t, err)

	valid, err := VerifySignature(parsed, data, sig)

	require.NoError(t, err)
	assert.False(t, valid)
}

// TestParsePublicKeyAKPRejectsMalformedKey asserts that a credential public key of type AKP which does not describe
// a key this library can verify with is rejected when it is parsed, so that it is never registered.
func TestParsePublicKeyAKPRejectsMalformedKey(t *testing.T) {
	valid := func(t *testing.T, alg COSEAlgorithmIdentifier) []byte {
		t.Helper()

		_, encoded := akpTestKey(t, alg)

		var key AKPPublicKeyData

		require.NoError(t, webauthncbor.Unmarshal(encoded, &key))

		return key.PublicKey
	}

	testCases := []struct {
		name string
		key  akpTestCOSEKey
		err  string
	}{
		{
			"ShouldRejectAlgorithmWhichIsNotMLDSA",
			akpTestCOSEKey{KeyType: int64(AKP), Algorithm: int64(AlgES256), PublicKey: valid(t, AlgMLDSA44)},
			"AKP key has unsupported algorithm ES256",
		},
		{
			"ShouldRejectAbsentAlgorithm",
			akpTestCOSEKey{KeyType: int64(AKP), PublicKey: valid(t, AlgMLDSA44)},
			"AKP key has unsupported algorithm 0",
		},
		{
			"ShouldRejectAbsentPublicKey",
			akpTestCOSEKey{KeyType: int64(AKP), Algorithm: int64(AlgMLDSA44)},
			"AKP key with algorithm ML-DSA-44 has invalid public key length 0, expected 1312",
		},
		{
			"ShouldRejectPublicKeyOfAnotherParameterSet",
			akpTestCOSEKey{KeyType: int64(AKP), Algorithm: int64(AlgMLDSA44), PublicKey: valid(t, AlgMLDSA65)},
			"AKP key with algorithm ML-DSA-44 has invalid public key length 1952, expected 1312",
		},
		{
			"ShouldRejectTruncatedPublicKey",
			akpTestCOSEKey{KeyType: int64(AKP), Algorithm: int64(AlgMLDSA87), PublicKey: valid(t, AlgMLDSA87)[:2591]},
			"AKP key with algorithm ML-DSA-87 has invalid public key length 2591, expected 2592",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := webauthncbor.Marshal(tc.key)

			require.NoError(t, err)

			parsed, err := ParsePublicKey(encoded)

			assert.Nil(t, parsed)
			require.EqualError(t, err, tc.err)
		})
	}
}

// TestParsePublicKeyAKPWireFormat asserts that the key material is read from the label RFC 9964 registers it at.
//
// Specification: §6. COSE Key Type AKP (https://www.rfc-editor.org/rfc/rfc9964#section-6)
func TestParsePublicKeyAKPWireFormat(t *testing.T) {
	testCases := []struct {
		name   string
		alg    COSEAlgorithmIdentifier
		params mldsa.Parameters
		header []byte
	}{
		{
			"ML-DSA-44", AlgMLDSA44, mldsa.MLDSA44(),
			// a3            map(3)
			//   01 07       1 (kty): 7 (AKP)
			//   03 38 2f    3 (alg): -48 (ML-DSA-44)
			//   20 59 0520  -1 (pub): bytes(1312)
			[]byte{0xa3, 0x01, 0x07, 0x03, 0x38, 0x2f, 0x20, 0x59, 0x05, 0x20},
		},
		{
			"ML-DSA-65", AlgMLDSA65, mldsa.MLDSA65(),
			[]byte{0xa3, 0x01, 0x07, 0x03, 0x38, 0x30, 0x20, 0x59, 0x07, 0xa0},
		},
		{
			"ML-DSA-87", AlgMLDSA87, mldsa.MLDSA87(),
			[]byte{0xa3, 0x01, 0x07, 0x03, 0x38, 0x31, 0x20, 0x59, 0x0a, 0x20},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			private, err := mldsa.NewPrivateKey(tc.params, akpTestSeed)

			require.NoError(t, err)

			public := private.PublicKey().Bytes()

			parsed, err := ParsePublicKey(append(append([]byte{}, tc.header...), public...))

			require.NoError(t, err)
			require.IsType(t, AKPPublicKeyData{}, parsed)

			key, _ := parsed.(AKPPublicKeyData)

			assert.Equal(t, int64(AKP), key.KeyType)
			assert.Equal(t, int64(tc.alg), key.Algorithm)
			assert.Equal(t, public, key.PublicKey)

			data := []byte("data to sign")

			sig, err := private.SignDeterministic(data, &mldsa.Options{})

			require.NoError(t, err)

			valid, err := VerifySignature(parsed, data, sig)

			require.NoError(t, err)
			assert.True(t, valid)

			t.Run("ShouldRejectKeyMaterialAtThePrivateLabel", func(t *testing.T) {
				header := append([]byte{}, tc.header...)
				header[6] = 0x21

				parsed, err := ParsePublicKey(append(header, public...))

				assert.Nil(t, parsed)
				require.EqualError(t, err, fmt.Sprintf("AKP key with algorithm %s has invalid public key length 0, expected %d", tc.alg, len(public)))
			})
		})
	}
}

func TestAKPPublicKeyDataVerifyValidatesKey(t *testing.T) {
	key := AKPPublicKeyData{
		PublicKeyData: PublicKeyData{
			KeyType:   int64(AKP),
			Algorithm: int64(AlgMLDSA44),
		},
		PublicKey: []byte{0x01, 0x02, 0x03},
	}

	valid, err := key.Verify([]byte("data to sign"), []byte("signature"))

	assert.False(t, valid)
	require.EqualError(t, err, "AKP key with algorithm ML-DSA-44 has invalid public key length 3, expected 1312")
}

func TestDisplayPublicKeyAKP(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			private, encoded := akpTestKey(t, tc.alg)

			display := DisplayPublicKey(encoded)

			require.NotEqual(t, keyCannotDisplay, display)

			block, rest := pem.Decode([]byte(display))

			require.NotNil(t, block)
			assert.Empty(t, rest)
			assert.Equal(t, "PUBLIC KEY", block.Type)

			public, err := x509.ParsePKIXPublicKey(block.Bytes)

			require.NoError(t, err)
			require.IsType(t, &mldsa.PublicKey{}, public)
			assert.True(t, private.PublicKey().Equal(public))
		})
	}

	t.Run("ShouldNotDisplayMalformedKey", func(t *testing.T) {
		encoded, err := webauthncbor.Marshal(akpTestCOSEKey{
			KeyType:   int64(AKP),
			Algorithm: int64(AlgMLDSA44),
			PublicKey: []byte{0x01, 0x02, 0x03},
		})

		require.NoError(t, err)
		assert.Equal(t, keyCannotDisplay, DisplayPublicKey(encoded))
	})
}

func TestParsePublicKeyAKPAcceptsAnyKeyOfTheRightLength(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			material := make([]byte, tc.publicKeySize)

			_, err := rand.Read(material)

			require.NoError(t, err)

			encoded, err := webauthncbor.Marshal(akpTestCOSEKey{
				KeyType:   int64(AKP),
				Algorithm: int64(tc.alg),
				PublicKey: material,
			})

			require.NoError(t, err)

			parsed, err := ParsePublicKey(encoded)

			require.NoError(t, err)
			require.IsType(t, AKPPublicKeyData{}, parsed)

			valid, err := VerifySignature(parsed, []byte("data to sign"), make([]byte, tc.signatureSize))
			require.NoError(t, err)
			assert.False(t, valid)
		})
	}
}

func TestSigAlgFromCOSEAlgMLDSA(t *testing.T) {
	testCases := []struct {
		alg      COSEAlgorithmIdentifier
		expected x509.SignatureAlgorithm
	}{
		{AlgMLDSA44, x509.MLDSA44},
		{AlgMLDSA65, x509.MLDSA65},
		{AlgMLDSA87, x509.MLDSA87},
	}

	for _, tc := range testCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			assert.Equal(t, tc.expected, SigAlgFromCOSEAlg(tc.alg))
		})
	}
}

func TestHasherFromCOSEAlgMLDSA(t *testing.T) {
	for _, tc := range akpTestAlgorithms {
		t.Run(tc.alg.String(), func(t *testing.T) {
			require.NotPanics(t, func() {
				h, ok := HasherFromCOSEAlg(tc.alg)

				assert.Nil(t, h)
				assert.False(t, ok)
			})
		})
	}
}

type akpTestCOSEKey struct {
	_struct   bool   `cbor:",keyasint"` //nolint:govet,staticcheck,unused
	KeyType   int64  `cbor:"1,keyasint"`
	Algorithm int64  `cbor:"3,keyasint"`
	PublicKey []byte `cbor:"-1,keyasint"`
}

func akpTestKey(t *testing.T, alg COSEAlgorithmIdentifier) (*mldsa.PrivateKey, []byte) {
	t.Helper()

	var params mldsa.Parameters

	switch alg {
	case AlgMLDSA44:
		params = mldsa.MLDSA44()
	case AlgMLDSA65:
		params = mldsa.MLDSA65()
	case AlgMLDSA87:
		params = mldsa.MLDSA87()
	default:
		t.Fatalf("akpTestKey called with algorithm %s which is not an ML-DSA parameter set", alg)
	}

	private, err := mldsa.GenerateKey(params)

	require.NoError(t, err)

	encoded, err := webauthncbor.Marshal(akpTestCOSEKey{
		KeyType:   int64(AKP),
		Algorithm: int64(alg),
		PublicKey: private.PublicKey().Bytes(),
	})

	require.NoError(t, err)

	return private, encoded
}

func akpTestSign(t *testing.T, private *mldsa.PrivateKey, data []byte) []byte {
	t.Helper()

	sig, err := private.Sign(nil, data, &mldsa.Options{})

	require.NoError(t, err)

	return sig
}

var akpTestAlgorithms = []struct {
	alg           COSEAlgorithmIdentifier
	publicKeySize int
	signatureSize int
}{
	{AlgMLDSA44, 1312, 2420},
	{AlgMLDSA65, 1952, 3309},
	{AlgMLDSA87, 2592, 4627},
}

var akpTestSeed = []byte{
	0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
}