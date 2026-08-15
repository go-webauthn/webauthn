package webauthncose

import (
	"crypto/sha256"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/x/crypto/secp256k1"
	secp256k1ecdsa "github.com/go-webauthn/x/crypto/secp256k1/ecdsa"
	"github.com/go-webauthn/x/encoding/asn1"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// secp256k1TestKey generates a secp256k1 key pair and returns the private key alongside the credential public key
// which a §5.8.5 conforming authenticator would report for it.
func secp256k1TestKey(t *testing.T) (*secp256k1.PrivateKey, EC2PublicKeyData) {
	t.Helper()

	private, err := secp256k1.GeneratePrivateKey()

	require.NoError(t, err)

	public := private.PubKey()

	return private, EC2PublicKeyData{
		PublicKeyData: PublicKeyData{
			KeyType:   int64(EllipticKey),
			Algorithm: int64(AlgES256K),
		},
		Curve:  int64(Secp256k1),
		XCoord: public.X().FillBytes(make([]byte, ecCoordSize)),
		YCoord: public.Y().FillBytes(make([]byte, ecCoordSize)),
	}
}

// secp256k1TestSign produces the DER encoded ECDSA signature over the SHA-256 digest of data which an authenticator
// using ES256K would return.
func secp256k1TestSign(t *testing.T, private *secp256k1.PrivateKey, data []byte) []byte {
	t.Helper()

	digest := sha256.Sum256(data)

	return secp256k1ecdsa.Sign(private, digest[:]).Serialize()
}

// TestEC2PublicKeyDataVerifySecp256k1 asserts that a credential public key with algorithm -47 (ES256K) verifies a
// signature its authenticator produced, and rejects one made over different data or by a different key.
func TestEC2PublicKeyDataVerifySecp256k1(t *testing.T) {
	private, key := secp256k1TestKey(t)

	data := []byte("data to sign")
	der := secp256k1TestSign(t, private, data)

	valid, err := key.Verify(data, der)

	require.NoError(t, err)
	assert.True(t, valid)

	t.Run("ShouldRejectSignatureOverDifferentData", func(t *testing.T) {
		valid, err := key.Verify([]byte("different data"), der)

		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("ShouldRejectSignatureFromDifferentKey", func(t *testing.T) {
		other, _ := secp256k1TestKey(t)

		valid, err := key.Verify(data, secp256k1TestSign(t, other, data))

		require.NoError(t, err)
		assert.False(t, valid)
	})

	t.Run("ShouldRejectSignatureVerifiedAgainstDifferentKey", func(t *testing.T) {
		_, other := secp256k1TestKey(t)

		valid, err := other.Verify(data, der)

		require.NoError(t, err)
		assert.False(t, valid)
	})
}

// TestEC2PublicKeyDataVerifySecp256k1RequiresCanonicalDER asserts that the DER strictness applied to the NIST curves
// applies equally to secp256k1, which is verified by a separate implementation and would otherwise be able to accept
// an encoding the specification does not permit.
func TestEC2PublicKeyDataVerifySecp256k1RequiresCanonicalDER(t *testing.T) {
	private, key := secp256k1TestKey(t)

	data := []byte("data to sign")
	der := secp256k1TestSign(t, private, data)

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

// TestEC2PublicKeyDataVerifySecp256k1RejectsScalarsOutOfRange asserts that a signature whose r or s falls outside the
// interval [1, n-1] is rejected. Both encode canonically, so the range check is the only thing standing between such
// a signature and the verification routine.
func TestEC2PublicKeyDataVerifySecp256k1RejectsScalarsOutOfRange(t *testing.T) {
	private, key := secp256k1TestKey(t)

	data := []byte("data to sign")
	der := secp256k1TestSign(t, private, data)

	var signature asn1.ECDSASignature

	_, err := asn1.Unmarshal(der, &signature)

	require.NoError(t, err)

	order := secp256k1.Params().N

	testCases := []struct {
		name string
		r, s *big.Int
	}{
		{"ShouldRejectZeroR", big.NewInt(0), signature.S},
		{"ShouldRejectZeroS", signature.R, big.NewInt(0)},
		{"ShouldRejectROverflowingOrder", order, signature.S},
		{"ShouldRejectSOverflowingOrder", signature.R, order},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			have, err := asn1.Marshal(asn1.ECDSASignature{R: tc.r, S: tc.s})

			require.NoError(t, err)

			valid, err := key.Verify(data, have)

			assert.False(t, valid)
			assert.EqualError(t, err, ErrSigNotProvidedOrInvalid.Error())
		})
	}
}

// TestParsePublicKeySecp256k1 asserts that a credential public key with algorithm -47 (ES256K) is accepted only when
// the point it carries is a valid secp256k1 point of the expected width.
func TestParsePublicKeySecp256k1(t *testing.T) {
	_, key := secp256k1TestKey(t)

	ec2 := func(x, y []byte) []byte {
		t.Helper()

		data, err := webauthncbor.Marshal(map[int64]any{
			1: int64(EllipticKey), 3: int64(AlgES256K), -1: int64(Secp256k1), -2: x, -3: y,
		})

		require.NoError(t, err)

		return data
	}

	t.Run("ShouldAcceptValidPoint", func(t *testing.T) {
		parsed, err := ParsePublicKey(ec2(key.XCoord, key.YCoord))

		require.NoError(t, err)
		require.IsType(t, EC2PublicKeyData{}, parsed)

		assert.Equal(t, key, parsed)
	})

	t.Run("ShouldRejectPointNotOnCurve", func(t *testing.T) {
		y := append([]byte{}, key.YCoord...)
		y[len(y)-1] ^= 0x01

		parsed, err := ParsePublicKey(ec2(key.XCoord, y))

		assert.Nil(t, parsed)
		assert.EqualError(t, err, "EC2 key point is not on curve")
	})

	t.Run("ShouldRejectCoordinateNotReducedModuloFieldPrime", func(t *testing.T) {
		prime := secp256k1.Params().P.FillBytes(make([]byte, ecCoordSize))

		parsed, err := ParsePublicKey(ec2(prime, key.YCoord))

		assert.Nil(t, parsed)
		assert.EqualError(t, err, "EC2 key point is not on curve")
	})

	t.Run("ShouldRejectShortCoordinate", func(t *testing.T) {
		parsed, err := ParsePublicKey(ec2(key.XCoord[1:], key.YCoord))

		assert.Nil(t, parsed)
		assert.EqualError(t, err, "EC2 key x or y coordinate has invalid length")
	})
}

// TestDisplayPublicKeySecp256k1 asserts that a secp256k1 credential public key renders as a PEM encoded
// SubjectPublicKeyInfo. The standard library has no object identifier for the curve and cannot marshal it, so
// without a dedicated encoding the key would silently render as undisplayable.
func TestDisplayPublicKeySecp256k1(t *testing.T) {
	_, key := secp256k1TestKey(t)

	data, err := webauthncbor.Marshal(map[int64]any{
		1: int64(EllipticKey), 3: int64(AlgES256K), -1: int64(Secp256k1), -2: key.XCoord, -3: key.YCoord,
	})

	require.NoError(t, err)

	block, rest := pem.Decode([]byte(DisplayPublicKey(data)))

	require.NotNil(t, block)
	require.Empty(t, rest)

	assert.Equal(t, "PUBLIC KEY", block.Type)

	var spki struct {
		Algorithm struct {
			Algorithm asn1.ObjectIdentifier
			Curve     asn1.ObjectIdentifier
		}
		PublicKey asn1.BitString
	}

	remaining, err := asn1.Unmarshal(block.Bytes, &spki)

	require.NoError(t, err)
	require.Empty(t, remaining)

	assert.Equal(t, asn1.ObjectIdentifier{1, 2, 840, 10045, 2, 1}, spki.Algorithm.Algorithm)
	assert.Equal(t, asn1.ObjectIdentifier{1, 3, 132, 0, 10}, spki.Algorithm.Curve)

	point := append([]byte{0x04}, key.XCoord...)
	point = append(point, key.YCoord...)

	assert.Equal(t, point, spki.PublicKey.Bytes)
}
