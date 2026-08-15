package protocol

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
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
			name:  "ValidRPIDSubdomain",
			value: "sub.example.com",
		},
		{
			name:  "ValidRPIDPunycode",
			value: "xn--bcher-kva.example",
		},
		{
			name:  "InvalidRPIDNonASCII",
			value: "café.example",
			err:   errDomainNotASCII.Error(),
		},
		{
			name:  "InvalidRPIDIPv4Shorthand",
			value: "127.1",
			err:   errDomainFinalLabelNumeric.Error(),
		},
		{
			name:  "InvalidRPIDNumericFinalLabel",
			value: "example.123",
			err:   errDomainFinalLabelNumeric.Error(),
		},
		{
			name:  "InvalidRPIDThreeOctetShorthand",
			value: "1.2.3",
			err:   errDomainFinalLabelNumeric.Error(),
		},
		{
			name:  "InvalidRPIDOutOfRangeOctets",
			value: "999.999.999.999",
			err:   errDomainFinalLabelNumeric.Error(),
		},
		{
			name:  "InvalidRPIDHexadecimalFinalLabel",
			value: "example.0x1",
			err:   errDomainFinalLabelNumeric.Error(),
		},
		{
			name:  "InvalidRPIDAllDigits",
			value: "2130706433",
			err:   errDomainFinalLabelNumeric.Error(),
		},
		{
			name:  "ValidRPIDUppercase",
			value: "EXAMPLE.COM",
		},
		{
			name:  "ValidRPIDUnderscoreIsNotForbidden",
			value: "exa_mple.com",
		},
		{
			name:  "ValidRPIDShortest",
			value: "a.b",
		},
		{
			name:  "InvalidRPIDUsingIPv4",
			value: "127.0.0.1",
			err:   errDomainIsIPAddress.Error(),
		},
		{
			name:  "InvalidRPIDUsingIPv4Alt",
			value: "1.1.1.1",
			err:   errDomainIsIPAddress.Error(),
		},
		{
			name:  "InvalidRPIDUsingIPv6",
			value: "2001:DB8:0:0:8:800:200C:417A",
			err:   errDomainIsIPAddress.Error(),
		},
		{
			name:  "InvalidRPIDUsingIPv6Alt",
			value: "::1",
			err:   errDomainIsIPAddress.Error(),
		},
		{
			name:  "InvalidRPIDNotDomain",
			value: "example",
			err:   errDomainNotADomain.Error(),
		},
		{
			name:  "InvalidRPIDTrailingDot",
			value: "example.com.",
			err:   errDomainEmptyLabel.Error(),
		},
		{
			name:  "InvalidRPIDLocalhostTrailingDot",
			value: "localhost.",
			err:   errDomainEmptyLabel.Error(),
		},
		{
			name:  "InvalidRPIDLeadingDot",
			value: ".example.com",
			err:   errDomainEmptyLabel.Error(),
		},
		{
			name:  "InvalidRPIDOnlyDots",
			value: "..",
			err:   errDomainEmptyLabel.Error(),
		},
		{
			name:  "InvalidRPIDEmptyLabel",
			value: "a..b",
			err:   errDomainEmptyLabel.Error(),
		},
		{
			name:  "InvalidRPIDHyphenLabels",
			value: "-.-",
			err:   errDomainLabelHyphen.Error(),
		},
		{
			name:  "InvalidRPIDLeadingHyphen",
			value: "-example.com",
			err:   errDomainLabelHyphen.Error(),
		},
		{
			name:  "InvalidRPIDTrailingHyphen",
			value: "example-.com",
			err:   errDomainLabelHyphen.Error(),
		},
		{
			name:  "InvalidRPIDTrailingHyphenLastLabel",
			value: "a.b-",
			err:   errDomainLabelHyphen.Error(),
		},
		{
			name:  "InvalidRPIDLeadingSpace",
			value: " example.com",
			err:   errDomainForbiddenCharacter.Error(),
		},
		{
			name:  "InvalidRPIDLabelTooLong",
			value: strings.Repeat("a", 64) + ".com",
			err:   errDomainLabelTooLong.Error(),
		},
		{
			name:  "InvalidRPIDTooLong",
			value: strings.Repeat(strings.Repeat("a", 63)+".", 4) + "com",
			err:   errDomainTooLong.Error(),
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

	testCases := []struct {
		name     string
		have     map[string]any
		expected struct {
			count int
			err   string
		}
	}{
		{
			name: "ShouldFailNotArray",
			have: map[string]any{"x5c": "not an array"},
			expected: struct {
				count int
				err   string
			}{
				err: "Error retrieving x5c value",
			},
		},
		{
			name: "ShouldFailEmptyArray",
			have: map[string]any{"x5c": []any{}},
			expected: struct {
				count int
				err   string
			}{
				err: "Error retrieving x5c value: empty array",
			},
		},
		{
			name: "ShouldFailParseError",
			have: map[string]any{"x5c": []any{[]byte("not a cert")}},
			expected: struct {
				count int
				err   string
			}{
				err: "Error retrieving x5c value: error occurred parsing values",
			},
		},
		{
			name: "ShouldSucceed",
			have: map[string]any{"x5c": []any{cert.Raw}},
			expected: struct {
				count int
				err   string
			}{
				count: 1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			x5c, x5cs, err := attStatementParseX5CS(tc.have, "x5c")

			if tc.expected.err == "" {
				assert.NoError(t, err)
				assert.Len(t, x5c, tc.expected.count)
				assert.Len(t, x5cs, tc.expected.count)
			} else {
				assert.Nil(t, x5c)
				assert.Nil(t, x5cs)
				assert.EqualError(t, err, tc.expected.err)
			}
		})
	}
}

func TestParseX5C(t *testing.T) {
	cert := testUtilsGenerateSelfSignedCert(t)

	testCases := []struct {
		name     string
		have     []any
		expected struct {
			count int
			err   string
		}
	}{
		{
			name: "ShouldFailNotByteArray",
			have: []any{"not bytes"},
			expected: struct {
				count int
				err   string
			}{
				err: "x5c[0] is not a byte array",
			},
		},
		{
			name: "ShouldFailInvalidCert",
			have: []any{[]byte("invalid cert der")},
			expected: struct {
				count int
				err   string
			}{
				err: "x5c[0] is not a valid certificate: x509: malformed certificate",
			},
		},
		{
			name: "ShouldSucceed",
			have: []any{cert.Raw},
			expected: struct {
				count int
				err   string
			}{
				count: 1,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			x5cs, err := parseX5C(tc.have)

			if tc.expected.err == "" {
				assert.NoError(t, err)
				assert.Len(t, x5cs, tc.expected.count)
			} else {
				assert.Nil(t, x5cs)
				assert.EqualError(t, err, tc.expected.err)
			}
		})
	}
}

func TestAttStatementCertChainVerify(t *testing.T) {
	ca := testUtilsGenerateSelfSignedCert(t)
	leaf := testUtilsGenerateLeafCert(t, ca)

	testCases := []struct {
		name string
		have struct {
			certs []*x509.Certificate
			roots *x509.CertPool
		}
		expected struct {
			empty bool
			err   string
		}
	}{
		{
			name: "ShouldFailEmptyChain",
			have: struct {
				certs []*x509.Certificate
				roots *x509.CertPool
			}{},
			expected: struct {
				empty bool
				err   string
			}{
				empty: true,
				err:   "empty chain",
			},
		},
		{
			name: "ShouldVerifyChainWithNilRoots",
			have: struct {
				certs []*x509.Certificate
				roots *x509.CertPool
			}{
				certs: []*x509.Certificate{leaf, ca},
			},
			expected: struct {
				empty bool
				err   string
			}{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			chains, err := attStatementCertChainVerify(tc.have.certs, tc.have.roots, false, time.Time{})

			if tc.expected.err == "" {
				assert.NoError(t, err)
				assert.NotEmpty(t, chains)
			} else {
				assert.EqualError(t, err, tc.expected.err)

				if tc.expected.empty {
					assert.Nil(t, chains)
				}
			}
		})
	}
}

// TestVerifyAttestationPublicKeyMatch asserts the credential public key is compared with the certificate public key
// for every key type the COSE parser produces. §8.4 and §8.8 require the two to match without restricting the key to
// ECDSA, so a key of another type is compared rather than refused.
func TestVerifyAttestationPublicKeyMatch(t *testing.T) {
	eccKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eccKeyBytes, err := webauthncbor.Marshal(webauthncose.EC2PublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.EllipticKey),
			Algorithm: int64(webauthncose.AlgES256),
		},
		Curve:  int64(webauthncose.P256),
		XCoord: padP256Coord(eccKey.X),
		YCoord: padP256Coord(eccKey.Y),
	})
	require.NoError(t, err)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	rsaKeyBytes, err := webauthncbor.Marshal(webauthncose.RSAPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.RSAKey),
			Algorithm: int64(webauthncose.AlgRS256),
		},
		Modulus:  rsaKey.N.Bytes(),
		Exponent: big.NewInt(int64(rsaKey.E)).Bytes(),
	})
	require.NoError(t, err)

	edKey, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)

	edKeyBytes, err := webauthncbor.Marshal(webauthncose.OKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.OctetKey),
			Algorithm: int64(webauthncose.AlgEdDSA),
		},
		Curve:  int64(webauthncose.Ed25519),
		XCoord: edKey,
	})
	require.NoError(t, err)

	edShortKeyBytes, err := webauthncbor.Marshal(webauthncose.OKPPublicKeyData{
		PublicKeyData: webauthncose.PublicKeyData{
			KeyType:   int64(webauthncose.OctetKey),
			Algorithm: int64(webauthncose.AlgEdDSA),
		},
		Curve:  int64(webauthncose.Ed25519),
		XCoord: edKey[:16],
	})
	require.NoError(t, err)

	differentECCKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	eccCert := testUtilsGenerateCertWithKey(t, &eccKey.PublicKey)
	differentCert := testUtilsGenerateCertWithKey(t, &differentECCKey.PublicKey)
	rsaCert := testUtilsGenerateCertWithKey(t, &rsaKey.PublicKey)
	edCert := testUtilsGenerateCertWithKey(t, edKey)

	testCases := []struct {
		name                string
		credentialPublicKey []byte
		cert                *x509.Certificate
		expected            any
		err                 string
	}{
		{
			name:                "ShouldMatchECDSA",
			credentialPublicKey: eccKeyBytes,
			cert:                eccCert,
			expected:            webauthncose.EC2PublicKeyData{},
		},
		{
			name:                "ShouldMatchRSA",
			credentialPublicKey: rsaKeyBytes,
			cert:                rsaCert,
			expected:            webauthncose.RSAPublicKeyData{},
		},
		{
			name:                "ShouldMatchEd25519",
			credentialPublicKey: edKeyBytes,
			cert:                edCert,
			expected:            webauthncose.OKPPublicKeyData{},
		},
		{
			name:                "ShouldFailInvalidPublicKey",
			credentialPublicKey: []byte("invalid"),
			cert:                eccCert,
			err:                 "Error parsing public key: Unsupported Public Key Type",
		},
		{
			name:                "ShouldFailKeyMismatch",
			credentialPublicKey: eccKeyBytes,
			cert:                differentCert,
			err:                 testUtilsErrKeyMismatch,
		},
		{
			// A credential public key of a different type to the certificate public key is a mismatch. It was
			// refused for not being ECDSA, which rejected the ECDSA certificate paired with it just the same.
			name:                "ShouldFailWhenCredentialKeyTypeDiffersFromCertificate",
			credentialPublicKey: edKeyBytes,
			cert:                eccCert,
			err:                 testUtilsErrKeyMismatch,
		},
		{
			name:                "ShouldFailWhenCertificateKeyTypeDiffersFromCredential",
			credentialPublicKey: eccKeyBytes,
			cert:                rsaCert,
			err:                 testUtilsErrKeyMismatch,
		},
		{
			// Rejected while parsing rather than while converting, which is the invariant letting the conversion
			// pass the coordinate to ed25519 without asserting its length.
			name:                "ShouldRejectMalformedOKPCoordinateWhileParsing",
			credentialPublicKey: edShortKeyBytes,
			cert:                edCert,
			err:                 "Error parsing public key: OKP key x coordinate has invalid length 16, expected 32",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			att := AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						CredentialPublicKey: tc.credentialPublicKey,
					},
				},
			}

			result, err := verifyAttestationPublicKeyMatch(att, tc.cert)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, result)

				return
			}

			require.NoError(t, err)
			assert.IsType(t, tc.expected, result)
		})
	}
}

func testUtilsGenerateSelfSignedCert(t *testing.T) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  true,
		KeyUsage:              x509.KeyUsageCertSign,
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

func testUtilsIssueCert(t *testing.T, template, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (*x509.Certificate, *ecdsa.PrivateKey) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	if parent == nil {
		parent, parentKey = template, key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key
}

func testUtilsCertTemplate(cn string, ca bool) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber:          big.NewInt(time.Now().UnixNano()),
		Subject:               pkix.Name{CommonName: cn},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		IsCA:                  ca,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
	}
}

// TestAttStatementCertChainVerifyExtKeyUsage ensures attestation certificates are not held to the crypto/x509 default
// KeyUsages of ExtKeyUsageServerAuth, which is applied to every certificate in the chain when KeyUsages is unset.
func TestAttStatementCertChainVerifyExtKeyUsage(t *testing.T) {
	testCases := []struct {
		name     string
		template func(*x509.Certificate)
	}{
		{
			name:     "ShouldAllowNoExtKeyUsage",
			template: func(cert *x509.Certificate) {},
		},
		{
			name: "ShouldAllowUnknownExtKeyUsageAIK",
			template: func(cert *x509.Certificate) {
				// tcg-kp-AIKCertificate, mandatory for TPM attestation certificates and not known to crypto/x509.
				cert.UnknownExtKeyUsage = []asn1.ObjectIdentifier{{2, 23, 133, 8, 3}}
			},
		},
		{
			name: "ShouldAllowClientAuthExtKeyUsage",
			template: func(cert *x509.Certificate) {
				cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
			},
		},
		{
			name: "ShouldAllowCodeSigningExtKeyUsage",
			template: func(cert *x509.Certificate) {
				cert.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageCodeSigning}
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			root, rootKey := testUtilsIssueCert(t, testUtilsCertTemplate("Test Root CA", true), nil, nil)

			roots := x509.NewCertPool()
			roots.AddCert(root)

			template := testUtilsCertTemplate("Test Attestation Leaf", false)

			tc.template(template)

			leaf, _ := testUtilsIssueCert(t, template, root, rootKey)

			chains, err := attStatementCertChainVerify([]*x509.Certificate{leaf, root}, roots, false, time.Time{})

			assert.NoError(t, err)
			assert.NotEmpty(t, chains)
		})
	}
}

// TestAttStatementCertChainVerifyLeafIsFirstCert ensures the certificate whose chain is verified is always x5c[0], the
// same certificate the attestation format handlers use for the signature, public key, and extension checks. Selecting
// any other element would allow an untrusted x5c[0] to be paired with an unrelated genuine certificate.
func TestAttStatementCertChainVerifyLeafIsFirstCert(t *testing.T) {
	root, rootKey := testUtilsIssueCert(t, testUtilsCertTemplate("Test Root CA", true), nil, nil)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	genuine, _ := testUtilsIssueCert(t, testUtilsCertTemplate("Test Genuine Leaf", false), root, rootKey)

	// A self-signed certificate which chains to nothing trusted, marked as a CA so that a leaf selection which skips CA
	// certificates would fall through to the genuine certificate instead.
	untrusted, _ := testUtilsIssueCert(t, testUtilsCertTemplate("Test Untrusted CA", true), nil, nil)

	chains, err := attStatementCertChainVerify([]*x509.Certificate{untrusted, genuine}, roots, true, time.Now().Add(time.Hour*8760))

	assert.Error(t, err)
	assert.Empty(t, chains)
}

// TestAttStatementCertChainVerifyMangledLeaf ensures an expired x5c[0] is still excluded from the intermediate pool and
// verifies successfully when mangling is enabled, as the mangle returns a copy rather than the original certificate.
func TestAttStatementCertChainVerifyMangledLeaf(t *testing.T) {
	root, rootKey := testUtilsIssueCert(t, testUtilsCertTemplate("Test Root CA", true), nil, nil)

	roots := x509.NewCertPool()
	roots.AddCert(root)

	template := testUtilsCertTemplate("Test Expired Leaf", false)
	template.NotBefore = time.Now().Add(-time.Hour * 48)
	template.NotAfter = time.Now().Add(-time.Hour * 24)

	expired, _ := testUtilsIssueCert(t, template, root, rootKey)

	chains, err := attStatementCertChainVerify([]*x509.Certificate{expired, root}, roots, false, time.Time{})

	assert.Error(t, err)
	assert.Empty(t, chains)

	chains, err = attStatementCertChainVerify([]*x509.Certificate{expired, root}, roots, true, time.Now().Add(time.Hour*8760))

	assert.NoError(t, err)
	assert.NotEmpty(t, chains)
}

const testUtilsErrKeyMismatch = "Certificate public key does not match public key in authData"

// testUtilsGenerateCertWithKey issues a self-signed certificate carrying the given public key, which may be of any
// type crypto/x509 can encode.
func testUtilsGenerateCertWithKey(t *testing.T, pub crypto.PublicKey) *x509.Certificate {
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

// padP256Coord left-pads a big.Int coordinate to 32 bytes (the fixed width for P-256).
// big.Int.Bytes() drops leading zeroes, which would cause COSE EC2 key validation to
// reject coordinates shorter than 32 bytes.
func padP256Coord(v *big.Int) []byte {
	const p256ByteLen = 32

	b := v.Bytes()

	if len(b) >= p256ByteLen {
		return b
	}

	padded := make([]byte, p256ByteLen)

	copy(padded[p256ByteLen-len(b):], b)

	return padded
}
