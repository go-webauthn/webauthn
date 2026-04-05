package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestValidateRPID(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		err   string
	}{
		{
			name:  "ValidRPIDDomain",
			value: "example.com",
		},
		{
			name:  "ValidRPIDLocalHost",
			value: "localhost",
		},
		{
			name:  "ValidRPIDUsingIPv4",
			value: "127.0.0.1",
		},
		{
			name:  "ValidRPIDUsingIPv4Alt",
			value: "1.1.1.1",
		},
		{
			name:  "ValidRPIDUsingIPv6",
			value: "2001:DB8:0:0:8:800:200C:417A",
		},
		{
			name:  "ValidRPIDUsingIPv6Alt",
			value: "::1",
		},
		{
			name:  "InvalidRPIDNotDomain",
			value: "example",
			err:   "the domain component must actually be a domain",
		},
		{
			name:  "InvalidRPIDScheme",
			value: "https://example.com",
			err:   "the scheme component must be empty",
		},
		{
			name:  "InvalidRPIDPort",
			value: "example.com:1234",
			err:   "the port component must be empty",
		},
		{
			name:  "InvalidRPIDPortWithScheme",
			value: "https://example.com:1234",
			err:   "the port component must be empty",
		},
		{
			name:  "InvalidRPIDPath",
			value: "example.com/example",
			err:   "the path component must be empty",
		},
		{
			name:  "InvalidRPIDQuery",
			value: "example.com?abc=123",
			err:   "the query component must be empty",
		},
		{
			name:  "InvalidRPIDFragment",
			value: "example.com#abc=123",
			err:   "the fragment component must be empty",
		},
		{
			name:  "InvalidRPIDPathWithScheme",
			value: "https://example.com/example",
			err:   "the path component must be empty",
		},
		{
			name:  "InvalidRPIDQueryWithScheme",
			value: "https://example.com?abc=123",
			err:   "the query component must be empty",
		},
		{
			name:  "InvalidRPIDFragmentWithScheme",
			value: "https://example.com#abc=123",
			err:   "the fragment component must be empty",
		},
		{
			name:  "InvalidEmpty",
			value: "",
			err:   "empty value provided",
		},
		{
			name:  "InvalidURI",
			value: "https://example\x00.com",
			err:   "parse \"https://example\\x00.com\": net/url: invalid control character in URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRPID(tc.value)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestMustParseX509Certificate(t *testing.T) {
	t.Run("ShouldPanic", func(t *testing.T) {
		assert.Panics(t, func() {
			mustParseX509Certificate([]byte("not a certificate"))
		})
	})
}

func TestMustParseX509CertificatePEM(t *testing.T) {
	t.Run("ShouldPanicInvalidPEM", func(t *testing.T) {
		assert.Panics(t, func() {
			mustParseX509CertificatePEM([]byte("not a pem"))
		})
	})
}

func TestAttStatementParseX5CS(t *testing.T) {
	cert := testUtilsGenerateSelfSignedCert(t)

	t.Run("ShouldFailNotArray", func(t *testing.T) {
		attStmt := map[string]any{
			"x5c": "not an array",
		}

		x5c, x5cs, err := attStatementParseX5CS(attStmt, "x5c")
		assert.Nil(t, x5c)
		assert.Nil(t, x5cs)
		assert.EqualError(t, err, "Error retrieving x5c value")
	})

	t.Run("ShouldFailEmptyArray", func(t *testing.T) {
		attStmt := map[string]any{
			"x5c": []any{},
		}

		x5c, x5cs, err := attStatementParseX5CS(attStmt, "x5c")
		assert.Nil(t, x5c)
		assert.Nil(t, x5cs)
		assert.EqualError(t, err, "Error retrieving x5c value: empty array")
	})

	t.Run("ShouldFailParseError", func(t *testing.T) {
		attStmt := map[string]any{
			"x5c": []any{[]byte("not a cert")},
		}

		x5c, x5cs, err := attStatementParseX5CS(attStmt, "x5c")
		assert.Nil(t, x5c)
		assert.Nil(t, x5cs)
		assert.EqualError(t, err, "Error retrieving x5c value: error occurred parsing values")
	})

	t.Run("ShouldSucceed", func(t *testing.T) {
		attStmt := map[string]any{
			"x5c": []any{cert.Raw},
		}

		x5c, x5cs, err := attStatementParseX5CS(attStmt, "x5c")
		require.NoError(t, err)
		assert.Len(t, x5c, 1)
		assert.Len(t, x5cs, 1)
	})
}

func TestParseX5C(t *testing.T) {
	t.Run("ShouldFailNotByteArray", func(t *testing.T) {
		x5cs, err := parseX5C([]any{"not bytes"})
		assert.Nil(t, x5cs)
		assert.EqualError(t, err, "x5c[0] is not a byte array")
	})

	t.Run("ShouldFailInvalidCert", func(t *testing.T) {
		x5cs, err := parseX5C([]any{[]byte("invalid cert der")})
		assert.Nil(t, x5cs)
		assert.EqualError(t, err, "x5c[0] is not a valid certificate: x509: malformed certificate")
	})

	t.Run("ShouldSucceed", func(t *testing.T) {
		cert := testUtilsGenerateSelfSignedCert(t)
		x5cs, err := parseX5C([]any{cert.Raw})
		require.NoError(t, err)
		assert.Len(t, x5cs, 1)
	})
}

func TestAttStatementCertChainVerify(t *testing.T) {
	t.Run("ShouldFailEmptyChain", func(t *testing.T) {
		chains, err := attStatementCertChainVerify(nil, nil, false, time.Time{})
		assert.Nil(t, chains)
		assert.EqualError(t, err, "empty chain")
	})

	t.Run("ShouldVerifyChainWithNilRoots", func(t *testing.T) {
		ca := testUtilsGenerateSelfSignedCert(t)
		leaf := testUtilsGenerateLeafCert(t, ca)

		chains, err := attStatementCertChainVerify([]*x509.Certificate{leaf, ca}, nil, false, time.Time{})
		require.NoError(t, err)
		assert.NotEmpty(t, chains)
	})
}

func TestVerifyAttestationECDSAPublicKeyMatch(t *testing.T) {
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	coseKey := webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: eccKey.PublicKey.X.Bytes(),
		YCoord: eccKey.PublicKey.Y.Bytes(),
	}

	coseKeyBytes, err := webauthncbor.Marshal(coseKey)
	require.NoError(t, err)

	cert := testUtilsGenerateCertWithKey(t, &eccKey.PublicKey)

	t.Run("ShouldSucceed", func(t *testing.T) {
		att := AttestationObject{
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					CredentialPublicKey: coseKeyBytes,
				},
			},
		}

		result, err := verifyAttestationECDSAPublicKeyMatch(att, cert)
		require.NoError(t, err)
		assert.Equal(t, int64(webauthncose.AlgES256), result.Algorithm)
	})

	t.Run("ShouldFailInvalidPublicKey", func(t *testing.T) {
		att := AttestationObject{
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					CredentialPublicKey: []byte("invalid"),
				},
			},
		}

		_, err := verifyAttestationECDSAPublicKeyMatch(att, cert)
		assert.EqualError(t, err, "Error parsing public key: Unsupported Public Key Type")
	})

	t.Run("ShouldFailNotECDSAKey", func(t *testing.T) {
		// Use an OKP key (EdDSA) instead of EC2.
		okpKey := webauthncose.OKPPublicKeyData{
			PublicKeyData: webauthncose.PublicKeyData{
				KeyType:   int64(webauthncose.OctetKey),
				Algorithm: int64(webauthncose.AlgEdDSA),
			},
			Curve:  1,
			XCoord: make([]byte, 32),
		}

		okpBytes, err := webauthncbor.Marshal(okpKey)
		require.NoError(t, err)

		att := AttestationObject{
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					CredentialPublicKey: okpBytes,
				},
			},
		}

		_, err = verifyAttestationECDSAPublicKeyMatch(att, cert)
		assert.EqualError(t, err, "Attestation public key is not ECDSA")
	})

	t.Run("ShouldFailCertNotECDSA", func(t *testing.T) {
		rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
		require.NoError(t, err)

		rsaCert := testUtilsGenerateCertWithRSAKey(t, &rsaKey.PublicKey)

		att := AttestationObject{
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					CredentialPublicKey: coseKeyBytes,
				},
			},
		}

		_, err = verifyAttestationECDSAPublicKeyMatch(att, rsaCert)
		assert.EqualError(t, err, "Credential public key is not ECDSA")
	})

	t.Run("ShouldFailKeyMismatch", func(t *testing.T) {
		differentKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		require.NoError(t, err)

		differentCert := testUtilsGenerateCertWithKey(t, &differentKey.PublicKey)

		att := AttestationObject{
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					CredentialPublicKey: coseKeyBytes,
				},
			},
		}

		_, err = verifyAttestationECDSAPublicKeyMatch(att, differentCert)
		assert.EqualError(t, err, "Certificate public key does not match public key in authData")
	})
}

func testUtilsGenerateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test CA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func testUtilsGenerateLeafCert(t *testing.T, ca *x509.Certificate) *x509.Certificate {
	t.Helper()

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// We need the CA's private key to sign. Generate a new CA key pair for signing.
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	// Recreate the CA cert with the new key so we can sign the leaf.
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
	}

	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	require.NoError(t, err)

	caCert, err := x509.ParseCertificate(caDER)
	require.NoError(t, err)

	*ca = *caCert

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	require.NoError(t, err)

	leafCert, err := x509.ParseCertificate(leafDER)
	require.NoError(t, err)

	return leafCert
}

func testUtilsGenerateCertWithKey(t *testing.T, pub *ecdsa.PublicKey) *x509.Certificate {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func testUtilsGenerateCertWithRSAKey(t *testing.T, pub *rsa.PublicKey) *x509.Certificate {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(3),
		Subject:      pkix.Name{CommonName: "Test RSA Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, pub, caKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}
