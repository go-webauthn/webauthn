package protocol

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/x/encoding/asn1"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestAttestationCertCheckSignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	require.NoError(t, err)

	cert := testSignatureCert(t, key)

	signed := []byte("authenticator data and client data hash")
	digest := sha256.Sum256(signed)

	der, err := ecdsa.SignASN1(rand.Reader, key, digest[:])

	require.NoError(t, err)

	ber := testSignatureBER(t, der)

	require.NotEqual(t, der, ber)

	testCases := []struct {
		name     string
		encoding ECDSASignatureEncoding
		sig      []byte
		err      string
	}{
		{
			"ShouldAcceptDERUnderDefault",
			ECDSASignatureEncodingDefault,
			der,
			"",
		},
		{
			"ShouldAcceptDERUnderDER",
			ECDSASignatureEncodingDER,
			der,
			"",
		},
		{
			"ShouldAcceptDERUnderBER",
			ECDSASignatureEncodingBER,
			der,
			"",
		},
		{
			"ShouldRejectBERUnderDefault",
			ECDSASignatureEncodingDefault,
			ber,
			"x509: ECDSA verification failure",
		},
		{
			"ShouldRejectBERUnderDER",
			ECDSASignatureEncodingDER,
			ber,
			"x509: ECDSA verification failure",
		},
		{
			"ShouldAcceptBERUnderBER",
			ECDSASignatureEncodingBER,
			ber,
			"",
		},
		{
			// A signature the normalizer can't decode fails the attestation rather than being passed on to the
			// verifier unchanged, so that enabling the encoding never widens what is accepted beyond BER integers.
			"ShouldRejectUndecodableUnderBER",
			ECDSASignatureEncodingBER,
			[]byte{0x30, 0x03, 0x02, 0x01},
			"Signature validation error: asn1: syntax error: data truncated",
		},
		{
			// A signature of a valid encoding but the wrong value is still rejected, as only the encoding is relaxed.
			"ShouldRejectWrongSignatureUnderBER",
			ECDSASignatureEncodingBER,
			testSignatureBER(t, mustSignASN1(t, key, sha256.Sum256([]byte("different data")))),
			"x509: ECDSA verification failure",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err = attestationCertCheckSignature(cert, x509.ECDSAWithSHA256, signed, tc.sig, SignaturePolicy{ECDSAEncoding: tc.encoding})

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func mustSignASN1(t *testing.T, key *ecdsa.PrivateKey, digest [32]byte) []byte {
	t.Helper()

	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])

	require.NoError(t, err)

	return sig
}

// TestAttestationCertCheckSignatureShouldNotAlterRSA checks that the encoding has no effect on a signature which
// isn't an ASN.1 ECDSA signature, as the normalizer would otherwise be handed a PKCS #1 v1.5 signature.
func TestAttestationCertCheckSignatureShouldNotAlterRSA(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)

	require.NoError(t, err)

	cert := testSignatureCert(t, key)

	signed := []byte("authenticator data and client data hash")
	digest := sha256.Sum256(signed)

	sig, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])

	require.NoError(t, err)

	for _, encoding := range []ECDSASignatureEncoding{ECDSASignatureEncodingDefault, ECDSASignatureEncodingDER, ECDSASignatureEncodingBER} {
		assert.NoError(t, attestationCertCheckSignature(cert, x509.SHA256WithRSA, signed, sig, SignaturePolicy{ECDSAEncoding: encoding}))
	}
}

// TestAttestationKeyVerifySignature checks that a signature verified against the credential public key accepts the
// same encodings under the same policy as one verified against a certificate, so that the two checks an attestation
// format may perform can't disagree.
func TestAttestationKeyVerifySignature(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	require.NoError(t, err)

	credentialPublicKey := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: padP256Coord(key.X),
		YCoord: padP256Coord(key.Y),
	}

	signed := []byte("authenticator data and client data hash")
	digest := sha256.Sum256(signed)

	der := mustSignASN1(t, key, digest)
	ber := testSignatureBER(t, der)

	testCases := []struct {
		name     string
		encoding ECDSASignatureEncoding
		sig      []byte
		valid    bool
		err      string
	}{
		{"ShouldAcceptDERUnderDefault", ECDSASignatureEncodingDefault, der, true, ""},
		{"ShouldAcceptDERUnderBER", ECDSASignatureEncodingBER, der, true, ""},
		{"ShouldRejectBERUnderDefault", ECDSASignatureEncodingDefault, ber, false, "Signature invalid or not provided"},
		{"ShouldAcceptBERUnderBER", ECDSASignatureEncodingBER, ber, true, ""},
		{"ShouldRejectUndecodableUnderBER", ECDSASignatureEncodingBER, []byte{0x30, 0x03, 0x02, 0x01}, false, "Signature validation error: asn1: syntax error: data truncated"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := attestationKeyVerifySignature(credentialPublicKey, signed, tc.sig, SignaturePolicy{ECDSAEncoding: tc.encoding})

			assert.Equal(t, tc.valid, valid)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

// TestAttestationSignaturePolicyGatesBasicAttestation checks the policy reaches a format handler and gates only the
// signature step of it, by observing that a BER signature fails the signature check under the default policy and
// gets past it to the certificate requirements under the BER encoding.
func TestAttestationSignaturePolicyGatesBasicAttestation(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	require.NoError(t, err)

	var (
		authData       = []byte("authenticator data")
		clientDataHash = []byte("client data hash")
	)

	digest := sha256.Sum256(append(append([]byte{}, authData...), clientDataHash...))

	ber := testSignatureBER(t, mustSignASN1(t, key, digest))

	// Under the default policy the BER signature fails the signature check.
	_, _, err = handleBasicAttestation(ber, clientDataHash, authData, nil, int64(webauthncose.AlgES256), []any{certDER}, nil, SignaturePolicy{})

	require.EqualError(t, err, "Signature validation error: x509: ECDSA verification failure")

	// Under the BER encoding the same signature passes it and the handler proceeds to the §8.2.1 certificate
	// requirements, which this certificate does not meet.
	_, _, err = handleBasicAttestation(ber, clientDataHash, authData, nil, int64(webauthncose.AlgES256), []any{certDER}, nil, SignaturePolicy{ECDSAEncoding: ECDSASignatureEncodingBER})

	require.EqualError(t, err, "Attestation Certificate Country Code is invalid")
}

func testSignatureShortFormLen(t *testing.T, n int) byte {
	t.Helper()

	require.Less(t, n, 0x80)

	return byte(n) //nolint:gosec // The length is bounds checked above.
}

func testSignatureBER(t *testing.T, der []byte) []byte {
	t.Helper()

	var signature asn1.ECDSASignature

	rest, err := asn1.Unmarshal(der, &signature)

	require.NoError(t, err)
	require.Empty(t, rest)

	pad := func(i *big.Int) []byte {
		var (
			content []byte
			err     error
		)

		content, err = asn1.Marshal(i)

		require.NoError(t, err)

		// The minimal encoding of an integer of the size carried by a signature has a short form length, so its
		// content octets follow the two octets of its tag and length.
		octets := append([]byte{0x00}, content[2:]...)

		return append([]byte{0x02, testSignatureShortFormLen(t, len(octets))}, octets...)
	}

	body := append(pad(signature.R), pad(signature.S)...)

	return append([]byte{0x30, testSignatureShortFormLen(t, len(body))}, body...)
}

func testSignatureCert(t *testing.T, key crypto.Signer) *x509.Certificate {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, key.Public(), key)

	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)

	require.NoError(t, err)

	return cert
}
