package webauthncose

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/x/encoding/asn1"
)

// TestEC2PublicKeyDataVerifyRequiresCanonicalDER checks that only the DER encoding of a signature is accepted. A
// decoder discards data trailing the signature and elements trailing the two integers within it rather than
// reporting either, and decodes a non-minimally encoded integer to the same value as the minimal one, so each of
// those would otherwise verify a signature the specification does not permit.
func TestEC2PublicKeyDataVerifyRequiresCanonicalDER(t *testing.T) {
	private, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	require.NoError(t, err)

	key := EC2PublicKeyData{
		PublicKeyData: PublicKeyData{
			KeyType:   int64(EllipticKey),
			Algorithm: int64(AlgES256),
		},
		Curve:  int64(P256),
		XCoord: private.X.FillBytes(make([]byte, 32)),
		YCoord: private.Y.FillBytes(make([]byte, 32)),
	}

	data := []byte("data to sign")
	digest := sha256.Sum256(data)

	der, err := ecdsa.SignASN1(rand.Reader, private, digest[:])

	require.NoError(t, err)

	// The DER encoding of the genuine signature verifies.
	valid, err := key.Verify(data, der)

	require.NoError(t, err)
	require.True(t, valid)

	var signature asn1.ECDSASignature

	rest, err := asn1.Unmarshal(der, &signature)

	require.NoError(t, err)
	require.Empty(t, rest)

	integer := func(t *testing.T, content []byte) []byte {
		t.Helper()

		require.Less(t, len(content), 0x80)

		return append([]byte{0x02, byte(len(content))}, content...) //nolint:gosec // The length is bounds checked above.
	}

	minimal := func(t *testing.T, i *big.Int) []byte {
		t.Helper()

		encoded, err := asn1.Marshal(i)

		require.NoError(t, err)

		return encoded
	}

	sequence := func(t *testing.T, elements ...[]byte) []byte {
		t.Helper()

		var content []byte

		for _, e := range elements {
			content = append(content, e...)
		}

		require.Less(t, len(content), 0x80)

		return append([]byte{0x30, byte(len(content))}, content...) //nolint:gosec // The length is bounds checked above.
	}

	padded := func(t *testing.T, i *big.Int) []byte {
		t.Helper()

		return integer(t, append([]byte{0x00}, minimal(t, i)[2:]...))
	}

	testCases := []struct {
		name string
		have []byte
	}{
		{
			"ShouldRejectTrailingDataAfterSignature",
			append(append([]byte{}, der...), 0xde, 0xad, 0xbe, 0xef),
		},
		{
			"ShouldRejectTrailingElementWithinSequence",
			sequence(t, minimal(t, signature.R), minimal(t, signature.S), integer(t, []byte{0x7f})),
		},
		{
			"ShouldRejectBERPaddedR",
			sequence(t, padded(t, signature.R), minimal(t, signature.S)),
		},
		{
			"ShouldRejectBERPaddedS",
			sequence(t, minimal(t, signature.R), padded(t, signature.S)),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.NotEqual(t, der, tc.have)

			valid, err := key.Verify(data, tc.have)

			assert.False(t, valid)
			assert.EqualError(t, err, ErrSigNotProvidedOrInvalid.Error())
		})
	}
}
