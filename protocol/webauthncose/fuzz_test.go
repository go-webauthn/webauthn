package webauthncose

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/x/crypto/secp256k1"
	"github.com/go-webauthn/x/encoding/asn1"

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

		key, err := ParsePublicKey(data)
		if err != nil {
			require.Equal(t, keyCannotDisplay, out, "a key which does not parse has nothing to display")

			return
		}

		pk := PublicKeyData{}

		require.NoError(t, webauthncbor.Unmarshal(data, &pk))

		switch COSEKeyType(pk.KeyType) {
		case OctetKey, EllipticKey, RSAKey:
			// Every way the rendering of these three can fail is a condition the parse has already rejected, so a
			// key which parses is a key which renders and a placeholder here is a disagreement between the two.
		default:
			// Algorithm key pair material is opaque to this package, and a build without the algorithms such a key
			// names renders nothing for it at all, so a placeholder is the documented outcome rather than a failure.
			return
		}

		block, rest := pem.Decode([]byte(out))

		require.NotNil(t, block, "a key which parses must render as a PEM block, got %q", out)
		require.Equal(t, "PUBLIC KEY", block.Type)
		require.Empty(t, rest)

		switch k := key.(type) {
		case OKPPublicKeyData:
			public, err := x509.ParsePKIXPublicKey(block.Bytes)

			require.NoError(t, err)
			require.Equal(t, ed25519.PublicKey(k.XCoord), public)
		case EC2PublicKeyData:
			if COSEAlgorithmIdentifier(k.Algorithm) == AlgES256K {
				info := pkixPublicKey{}

				trailing, err := asn1.Unmarshal(block.Bytes, &info)

				require.NoError(t, err)
				require.Empty(t, trailing)
				require.True(t, info.Algorithm.Algorithm.Equal(oidPublicKeyECDSA))
				require.True(t, info.Algorithm.Parameters.Equal(oidNamedCurveSecp256k1))
				require.Equal(t, secp256k1PointUncompressed(&k), info.PublicKey.Bytes)

				_, err = secp256k1.ParsePubKey(info.PublicKey.Bytes)

				require.NoError(t, err)

				break
			}

			public, err := x509.ParsePKIXPublicKey(block.Bytes)

			require.NoError(t, err)

			ec, ok := public.(*ecdsa.PublicKey)

			require.True(t, ok)
			require.Equal(t, new(big.Int).SetBytes(k.XCoord), ec.X)
			require.Equal(t, new(big.Int).SetBytes(k.YCoord), ec.Y)
		case RSAPublicKeyData:
			public, err := x509.ParsePKIXPublicKey(block.Bytes)

			require.NoError(t, err)

			decoded, ok := public.(*rsa.PublicKey)

			require.True(t, ok)
			require.Equal(t, new(big.Int).SetBytes(k.Modulus), decoded.N)

			exponent, err := ParseRSAPublicKeyDataExponent(&k)

			require.NoError(t, err)
			require.Equal(t, exponent, decoded.E)
		default:
			require.Fail(t, "a modelled key type must parse into its own structure", "key type %d", pk.KeyType)
		}
	})
}

// Supporting variables and functions.

// The credential public keys of the WebAuthn Level 3 §16 end-to-end test vectors, covering every key type and every
// curve the library parses. These are wire encodings taken from the specification rather than encodings this package
// produced, so a seed remains a key the specification describes even where the tags the encoder writes and the tags
// the parser reads agree with each other but not with COSE.
//
// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors
var fuzzSpecVectorsCredentialPublicKeys = []string{
	// §16.2 None Attestation - ES256.
	"a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
	// §16.3 Self Attestation (Packed) - ES256.
	"a5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
	// §16.4 None Attestation - ES256 - Cross Origin.
	"a501020326200121582022200a473f90b11078851550d03b4e44a2279f8c4eca27b3153dedfe03e4e97d225820cbd0be95e746ad6f5a8191be11756e4c0420e72f65b466d39bc56b8b123a9c6e",
	// §16 ES384, whose coordinates are 48 bytes rather than 32.
	"a5010203382220022158304866bd8b01da789e9eb806e5eab05ae5a638542296ab057a2f1bbce9b58f8a08b9171390b58a37ac7fffc2c5f45857da2258302a0b024c7f4b72072a1f96bd30a7261aae9571dd39870eb29e55c0941c6b08e89629a1ea1216aa64ce57c2807bf3901a",
	// §16 ES512, whose coordinates are 66 bytes.
	"a5010203382320032158420083240a2c3ad21a3dc0a6daa3d8bc05a46d7cd9825ba010ae2a22686c2d6d663d7d5f678987fb1e767542e63dc197ae915e25f8ee284651af29066910a2cc083f50225842017337df47ab5cce5d716ef8caffa97a3012689b1f326ea6c43a1ba9596c72f71f0122390143552b42be772b4c35ffb961220c743b486a601ea4cb6d5412f5b078d3",
	// §16 RS256, the only vector carrying an RSA modulus and exponent.
	"a4010303390100205901b403fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff800000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000012143010001",
	// §16 EdDSA, the only vector carrying an octet key.
	"a401010327200621582044e06ddd331c36a8dc667bab52bcae63486c916aa5e339e6acebaa84934bf832",
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
