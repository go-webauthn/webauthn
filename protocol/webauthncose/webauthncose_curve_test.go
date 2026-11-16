package webauthncose

import (
	"crypto/ecdh"
	"crypto/ed25519"
	"crypto/rand"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// TestParsePublicKeyCurveBinding asserts the binding §5.8.5 places between a credential public key's algorithm and
// the curve it names.
//
// The specification requires a key with algorithm -7 (ES256) to specify 1 (P-256) as its crv, -35 (ES384) to specify
// 2 (P-384), -36 (ES512) to specify 3 (P-521), and -8 (EdDSA) to specify 6 (Ed25519). The fully specified algorithms
// -9/-51/-52 (ESP256/384/512) and -19 (Ed25519) carry no such requirement because the algorithm identifier fixes the
// curve on its own, so for those a crv is optional but may not contradict the algorithm.
//
// Specification: §5.8.5. Cryptographic Algorithm Identifier (https://www.w3.org/TR/webauthn-3/#sctn-alg-identifier)
func TestParsePublicKeyCurveBinding(t *testing.T) {
	okpPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	p256, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)

	p256Pub := p256.PublicKey().Bytes()
	p256X, p256Y := p256Pub[1:33], p256Pub[33:65]

	p384, err := ecdh.P384().GenerateKey(rand.Reader)
	require.NoError(t, err)

	p384Pub := p384.PublicKey().Bytes()
	p384X, p384Y := p384Pub[1:49], p384Pub[49:97]

	ec2 := func(alg COSEAlgorithmIdentifier, crv any, x, y []byte) map[int64]any {
		key := map[int64]any{1: int64(EllipticKey), 3: int64(alg), -2: x, -3: y}

		if crv != nil {
			key[-1] = crv
		}

		return key
	}

	okp := func(alg COSEAlgorithmIdentifier, crv any) map[int64]any {
		key := map[int64]any{1: int64(OctetKey), 3: int64(alg), -2: []byte(okpPub)}

		if crv != nil {
			key[-1] = crv
		}

		return key
	}

	testCases := []struct {
		name string
		key  map[int64]any
		err  string
	}{
		{
			name: "ShouldAcceptES256WithP256",
			key:  ec2(AlgES256, int64(P256), p256X, p256Y),
		},
		{
			name: "ShouldRejectES256WithP521",
			key:  ec2(AlgES256, int64(P521), p256X, p256Y),
			err:  "EC2 key with algorithm ES256 must specify curve P-256 but it specified curve P-521",
		},
		{
			name: "ShouldRejectES256WithoutCurve",
			key:  ec2(AlgES256, nil, p256X, p256Y),
			err:  "EC2 key with algorithm ES256 must specify curve P-256 but it specified no curve",
		},
		{
			name: "ShouldAcceptES384WithP384",
			key:  ec2(AlgES384, int64(P384), p384X, p384Y),
		},
		{
			name: "ShouldRejectES384WithP256",
			key:  ec2(AlgES384, int64(P256), p384X, p384Y),
			err:  "EC2 key with algorithm ES384 must specify curve P-384 but it specified curve P-256",
		},
		{
			name: "ShouldAcceptESP256WithP256",
			key:  ec2(AlgESP256, int64(P256), p256X, p256Y),
		},
		{
			// The fully specified algorithms name the curve themselves, so §5.8.5 does not require the crv.
			name: "ShouldAcceptESP256WithoutCurve",
			key:  ec2(AlgESP256, nil, p256X, p256Y),
		},
		{
			name: "ShouldRejectESP256WithP384",
			key:  ec2(AlgESP256, int64(P384), p256X, p256Y),
			err:  "EC2 key with algorithm ESP256 must specify curve P-256 but it specified curve P-384",
		},
		{
			name: "ShouldAcceptEdDSAWithEd25519",
			key:  okp(AlgEdDSA, int64(Ed25519)),
		},
		{
			name: "ShouldRejectEdDSAWithX25519",
			key:  okp(AlgEdDSA, int64(X25519)),
			err:  "OKP key with algorithm EdDSA must specify curve Ed25519 but it specified curve X25519",
		},
		{
			name: "ShouldRejectEdDSAWithoutCurve",
			key:  okp(AlgEdDSA, nil),
			err:  "OKP key with algorithm EdDSA must specify curve Ed25519 but it specified no curve",
		},
		{
			name: "ShouldAcceptEd25519WithoutCurve",
			key:  okp(AlgEd25519, nil),
		},
		{
			name: "ShouldRejectEd25519WithEd448",
			key:  okp(AlgEd25519, int64(Ed448)),
			err:  "OKP key with algorithm Ed25519 must specify curve Ed25519 but it specified curve Ed448",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := webauthncbor.Marshal(tc.key)
			require.NoError(t, err)

			key, err := ParsePublicKey(data)

			if tc.err != "" {
				assert.Nil(t, key)
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, key)
		})
	}
}

// TestOKPPublicKeyDataCurveDecodes asserts the crv parameter of an OKP key reaches the decoded structure. Without a
// CBOR tag on the field the parameter is silently dropped, leaving the §5.8.5 curve requirement unenforceable and
// the exported member permanently zero.
func TestOKPPublicKeyDataCurveDecodes(t *testing.T) {
	okpPub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	data, err := webauthncbor.Marshal(map[int64]any{
		1: int64(OctetKey), 3: int64(AlgEdDSA), -1: int64(Ed25519), -2: []byte(okpPub),
	})
	require.NoError(t, err)

	key, err := ParsePublicKey(data)
	require.NoError(t, err)

	require.IsType(t, OKPPublicKeyData{}, key)

	assert.Equal(t, int64(Ed25519), key.(OKPPublicKeyData).Curve)
}
