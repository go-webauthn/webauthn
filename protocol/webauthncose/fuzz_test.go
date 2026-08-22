package webauthncose

import (
	"encoding/hex"
	"encoding/pem"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func FuzzParsePublicKey(f *testing.F) {
	for _, seed := range fuzzSeedsCOSEKeys(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		key, err := ParsePublicKey(data)
		if err != nil {
			require.Nil(t, key)

			return
		}

		pk := PublicKeyData{}

		require.NoError(t, webauthncbor.Unmarshal(data, &pk))

		switch COSEKeyType(pk.KeyType) {
		case OctetKey:
			require.IsType(t, OKPPublicKeyData{}, key)
		case EllipticKey:
			require.IsType(t, EC2PublicKeyData{}, key)
		case RSAKey:
			require.IsType(t, RSAPublicKeyData{}, key)
		case AKP:
			// The algorithm key pair structures are build tagged and are not modelled here, so the type is left to
			// the parser. That it returned without an error is the property under test.
		default:
			require.Fail(t, "a key type with no parser must not parse", "key type %d", pk.KeyType)
		}
	})
}

func FuzzDisplayPublicKey(f *testing.F) {
	for _, seed := range fuzzSeedsCOSEKeys(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		out := DisplayPublicKey(data)

		if _, err := ParsePublicKey(data); err != nil {
			require.Equal(t, keyCannotDisplay, out, "a key which does not parse has nothing to display")

			return
		}

		if out == keyCannotDisplay || out == "Cannot display key of this type" {
			return
		}

		block, rest := pem.Decode([]byte(out))

		require.NotNil(t, block, "output which is not a placeholder must be a PEM block")
		require.Equal(t, "PUBLIC KEY", block.Type)
		require.Empty(t, rest)
	})
}

// Supporting variables and functions.

// The elliptic curve seeds are the credential public keys from the WebAuthn Level 3 §16 end-to-end test vectors. The
// remaining seeds are encoded from key structures rather than repeated as constants, as the parser reads them back
// through the same tags the encoder writes.
//
// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors
var fuzzSpecVectorsCredentialPublicKeys = []string{
	// §16.2 None Attestation - ES256.
	"a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
	// §16.3 Self Attestation (Packed) - ES256.
	"a5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
	// §16.4 None Attestation - ES256 - Cross Origin.
	"a501020326200121582022200a473f90b11078851550d03b4e44a2279f8c4eca27b3153dedfe03e4e97d225820cbd0be95e746ad6f5a8191be11756e4c0420e72f65b466d39bc56b8b123a9c6e",
}

func fuzzSeedsCOSEKeys(tb testing.TB) (seeds [][]byte) {
	tb.Helper()

	for _, vector := range fuzzSpecVectorsCredentialPublicKeys {
		data, err := hex.DecodeString(vector)
		require.NoError(tb, err)

		seeds = append(seeds, data)
	}

	okp := OKPPublicKeyData{
		PublicKeyData: PublicKeyData{KeyType: int64(OctetKey), Algorithm: int64(AlgEdDSA)},
		Curve:         int64(Ed25519),
		XCoord:        make([]byte, 32),
	}

	rsa := RSAPublicKeyData{
		PublicKeyData: PublicKeyData{KeyType: int64(RSAKey), Algorithm: int64(AlgRS256)},
		Modulus:       make([]byte, 256),
		Exponent:      []byte{0x01, 0x00, 0x01},
	}

	rsa.Modulus[0] = 0xc0

	for _, key := range []any{okp, rsa, PublicKeyData{KeyType: int64(OctetKey), Algorithm: int64(AlgEdDSA)}} {
		data, err := webauthncbor.Marshal(key)
		require.NoError(tb, err)

		seeds = append(seeds, data)
	}

	return seeds
}
