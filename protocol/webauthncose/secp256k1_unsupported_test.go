//go:build webauthn_no_es256k

package webauthncose

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// TestParsePublicKeyES256KUnsupported asserts that a build without ES256K support rejects a valid ES256K credential
// public key when it is parsed, so a Relying Party never registers a credential it would be unable to authenticate
// with.
func TestParsePublicKeyES256KUnsupported(t *testing.T) {
	parsed, err := ParsePublicKey(secp256k1TestCOSEKey(t))

	assert.Nil(t, parsed)
	require.EqualError(t, err, "Unsupported EC2 algorithm")
}

// TestVerifyES256KUnsupported asserts that an ES256K key which reaches verification without being parsed is refused
// rather than verified some other way.
func TestVerifyES256KUnsupported(t *testing.T) {
	key := secp256k1TestPoint(t)

	valid, err := key.Verify([]byte("data to sign"), []byte("signature"))

	assert.False(t, valid)
	require.EqualError(t, err, "Unsupported EC2 algorithm")
}

// TestDisplayPublicKeyES256KUnsupported asserts that an ES256K key is reported as one which cannot be displayed.
func TestDisplayPublicKeyES256KUnsupported(t *testing.T) {
	assert.Equal(t, keyCannotDisplay, DisplayPublicKey(secp256k1TestCOSEKey(t)))
}

// requireSecp256k1PKIX fails, as no ES256K key parses on this build and so none can reach rendering.
func requireSecp256k1PKIX(t *testing.T, _ *EC2PublicKeyData, _ []byte) {
	t.Helper()

	require.Fail(t, "an ES256K key must not parse on a build without ES256K support")
}

// secp256k1TestPoint returns the secp256k1 base point as an ES256K credential public key. It is a valid point on the
// curve which a build without ES256K support has no implementation to derive.
//
// Specification: §2.4.1 (https://www.secg.org/sec2-v2.pdf)
func secp256k1TestPoint(t *testing.T) EC2PublicKeyData {
	t.Helper()

	return EC2PublicKeyData{
		PublicKeyData: PublicKeyData{
			KeyType:   int64(EllipticKey),
			Algorithm: int64(AlgES256K),
		},
		Curve:  int64(Secp256k1),
		XCoord: MustDecodeHex(t, "79be667ef9dcbbac55a06295ce870b07029bfcdb2dce28d959f2815b16f81798"),
		YCoord: MustDecodeHex(t, "483ada7726a3c4655da4fbfc0e1108a8fd17b448a68554199c47d08ffb10d4b8"),
	}
}

func secp256k1TestCOSEKey(t *testing.T) []byte {
	t.Helper()

	key := secp256k1TestPoint(t)

	data, err := webauthncbor.Marshal(map[int64]any{
		1: int64(EllipticKey), 3: int64(AlgES256K), -1: int64(Secp256k1), -2: key.XCoord, -3: key.YCoord,
	})

	require.NoError(t, err)

	return data
}
