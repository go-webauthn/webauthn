package metadata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateChainMalformed(t *testing.T) {
	testCases := []struct {
		name  string
		chain []any
	}{
		{
			name:  "ShouldHandleEmptyChain",
			chain: []any{},
		},
		{
			name:  "ShouldHandleSingleElementChain",
			chain: []any{"leaf"},
		},
		{
			name:  "ShouldHandleNonStringLeaf",
			chain: []any{1, "intermediate"},
		},
		{
			name:  "ShouldHandleNonStringIntermediate",
			chain: []any{"leaf", 2},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				valid, err := validateChain(ConformanceMDSRoot, tc.chain, false)

				assert.False(t, valid)
				assert.Equal(t, errInvalidCertificateChain, err)
			})
		})
	}
}

func TestDecodeBytesRejectsX509URIHeader(t *testing.T) {
	decoder, err := NewDecoder()
	require.NoError(t, err)

	encode := func(v string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(v))
	}

	token := strings.Join([]string{
		encode(`{"alg":"ES256","typ":"JWT","x5u":"https://mds.example.com/signing.pem"}`),
		encode(`{"no":1,"nextUpdate":"2025-01-01","entries":[]}`),
		encode("signature"),
	}, ".")

	payload, err := decoder.DecodeBytes([]byte(token))

	assert.Nil(t, payload)
	require.Error(t, err)
	assert.ErrorContains(t, err, "x5u encountered in header of metadata TOC payload")
}

func TestValidateChainFallbackRoot(t *testing.T) {
	valid, err := validateChain(ConformanceMDSRoot, []any{ConformanceMDSRoot}, false)

	assert.True(t, valid)
	assert.NoError(t, err)
}

func TestValidateChainDepth(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 1, "root", nil, nil, true)
	first, firstKey, firstEncoded := newTestCertificate(t, 2, "intermediate one", root, rootKey, true)
	second, secondKey, secondEncoded := newTestCertificate(t, 3, "intermediate two", first, firstKey, true)

	_, _, shallowEncoded := newTestCertificate(t, 4, "shallow leaf", first, firstKey, false)
	_, _, deepEncoded := newTestCertificate(t, 5, "deep leaf", second, secondKey, false)

	testCases := []struct {
		name  string
		chain []any
		valid bool
	}{
		{
			name:  "ShouldValidateSingleIntermediate",
			chain: []any{shallowEncoded, firstEncoded},
			valid: true,
		},
		{
			name:  "ShouldValidateTwoIntermediates",
			chain: []any{deepEncoded, secondEncoded, firstEncoded},
			valid: true,
		},
		{
			name:  "ShouldRejectIncompleteChain",
			chain: []any{deepEncoded, secondEncoded},
			valid: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := validateChain(rootEncoded, tc.chain, false)

			assert.Equal(t, tc.valid, valid)

			if tc.valid {
				assert.NoError(t, err)
			} else {
				assert.Error(t, err)
			}
		})
	}
}

func newTestCertificate(t *testing.T, serial int64, name string, parent *x509.Certificate, parentKey *ecdsa.PrivateKey, ca bool, mutators ...func(template *x509.Certificate)) (cert *x509.Certificate, key *ecdsa.PrivateKey, encoded string) {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               pkix.Name{CommonName: name},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour * 24),
		BasicConstraintsValid: true,
		IsCA:                  ca,
	}

	if ca {
		template.KeyUsage = x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	} else {
		template.KeyUsage = x509.KeyUsageDigitalSignature
		template.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageAny}
	}

	for _, mutator := range mutators {
		mutator(template)
	}

	signer, signerKey := template, key

	if parent != nil {
		signer, signerKey = parent, parentKey
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signer, &key.PublicKey, signerKey)
	require.NoError(t, err)

	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, key, base64.StdEncoding.EncodeToString(der)
}

// unreachableCRL points the certificate at a distribution point which cannot be reached, so that its revocation status
// cannot be determined.
func unreachableCRL(template *x509.Certificate) {
	template.CRLDistributionPoints = []string{"http://127.0.0.1:1/crl"}
}

// newRevocationListServer serves a CRL signed by the given issuer which lists the given serials as revoked.
func newRevocationListServer(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, revoked ...int64) *httptest.Server {
	t.Helper()

	return newRevocationListServerWithTemplate(t, issuer, issuerKey, nil, revoked...)
}

func newRevocationListServerWithTemplate(t *testing.T, issuer *x509.Certificate, issuerKey *ecdsa.PrivateKey, mutator func(template *x509.RevocationList), revoked ...int64) *httptest.Server {
	t.Helper()

	entries := make([]x509.RevocationListEntry, len(revoked))

	for i, serial := range revoked {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   big.NewInt(serial),
			RevocationTime: time.Now().Add(-time.Hour),
		}
	}

	template := &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}

	if mutator != nil {
		mutator(template)
	}

	der, err := x509.CreateRevocationList(rand.Reader, template, issuer, issuerKey)
	require.NoError(t, err)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/pkix-crl")

		_, _ = w.Write(der)
	}))

	t.Cleanup(server.Close)

	return server
}

func TestValidateChainRevocation(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 20, "root", nil, nil, true)
	inter, interKey, interEncoded := newTestCertificate(t, 21, "intermediate", root, rootKey, true)

	// A certificate whose status cannot be determined is treated as not revoked, as the distribution point is not
	// reliably reachable at the moment a blob is decoded.
	_, _, leafUnknown := newTestCertificate(t, 22, "leaf unknown", inter, interKey, false, unreachableCRL)

	leafCRL := newRevocationListServer(t, inter, interKey, 23)

	_, _, leafRevoked := newTestCertificate(t, 23, "leaf revoked", inter, interKey, false, func(template *x509.Certificate) {
		template.CRLDistributionPoints = []string{leafCRL.URL}
	})

	interCRL := newRevocationListServer(t, root, rootKey, 25)

	interRevoked, interRevokedKey, interRevokedEncoded := newTestCertificate(t, 25, "intermediate revoked", root, rootKey, true, func(template *x509.Certificate) {
		template.CRLDistributionPoints = []string{interCRL.URL}
	})

	_, _, leafOfRevoked := newTestCertificate(t, 26, "leaf of revoked", interRevoked, interRevokedKey, false)

	interUnknown, interUnknownKey, interUnknownEncoded := newTestCertificate(t, 27, "intermediate unknown", root, rootKey, true, unreachableCRL)

	_, _, leafOfUnknown := newTestCertificate(t, 28, "leaf of unknown", interUnknown, interUnknownKey, false)
	_, _, leafOK := newTestCertificate(t, 24, "leaf", inter, interKey, false)

	testCases := []struct {
		name     string
		chain    []any
		hardfail bool
		valid    bool
		err      error
	}{
		{
			name:  "ShouldPermitLeafWithUnknownStatus",
			chain: []any{leafUnknown, interEncoded},
			valid: true,
		},
		{
			name:  "ShouldPermitDeterminableChain",
			chain: []any{leafOK, interEncoded},
			valid: true,
		},
		{
			name:  "ShouldRejectRevokedLeaf",
			chain: []any{leafRevoked, interEncoded},
			valid: false,
			err:   errLeafCertRevoked,
		},
		{
			name:  "ShouldRejectRevokedIntermediate",
			chain: []any{leafOfRevoked, interRevokedEncoded},
			valid: false,
			err:   errIntermediateCertRevoked,
		},
		{
			name:  "ShouldPermitIntermediateWithUnknownStatus",
			chain: []any{leafOfUnknown, interUnknownEncoded},
			valid: true,
		},
		{
			name:     "ShouldRejectLeafWithUnknownStatusWhenHardFail",
			chain:    []any{leafUnknown, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errCRLUnavailable,
		},
		{
			name:     "ShouldRejectIntermediateWithUnknownStatusWhenHardFail",
			chain:    []any{leafOfUnknown, interUnknownEncoded},
			hardfail: true,
			valid:    false,
			err:      errCRLUnavailable,
		},
		{
			name:     "ShouldPermitDeterminableChainWhenHardFail",
			chain:    []any{leafOK, interEncoded},
			hardfail: true,
			valid:    true,
		},
		{
			name:     "ShouldRejectRevokedLeafWhenHardFail",
			chain:    []any{leafRevoked, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errLeafCertRevoked,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := validateChain(rootEncoded, tc.chain, tc.hardfail)

			assert.Equal(t, tc.valid, valid)

			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestDecodeBytesRevocationHardFail(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 40, "root", nil, nil, true)
	inter, interKey, interEncoded := newTestCertificate(t, 41, "intermediate", root, rootKey, true)

	_, leafKey, leafEncoded := newTestCertificate(t, 42, "leaf unknown", inter, interKey, false, unreachableCRL)

	token := jwt.NewWithClaims(jwt.SigningMethodES256, jwt.MapClaims{"no": 1, "nextUpdate": "2099-01-01"})

	token.Header[HeaderX509Certificate] = []string{leafEncoded, interEncoded}

	blob, err := token.SignedString(leafKey)
	require.NoError(t, err)

	decoder, err := NewDecoder(WithRootCertificate(rootEncoded))
	require.NoError(t, err)

	payload, err := decoder.DecodeBytes([]byte(blob))
	require.NoError(t, err)
	assert.Equal(t, 1, payload.Number)

	decoder, err = NewDecoder(WithRootCertificate(rootEncoded), WithRevocationHardFail())
	require.NoError(t, err)

	_, err = decoder.DecodeBytes([]byte(blob))
	assert.ErrorIs(t, err, errCRLUnavailable)
}

func TestValidateChainRevocationHardFailExemptsTrustAnchor(t *testing.T) {
	_, _, rootEncoded := newTestCertificate(t, 60, "root unknown", nil, nil, true, unreachableCRL)

	valid, err := validateChain(rootEncoded, []any{rootEncoded}, true)

	assert.True(t, valid)
	assert.NoError(t, err)
}

func TestValidateChainDoesNotCheckRevocationOfUntrustedChain(t *testing.T) {
	_, _, rootEncoded := newTestCertificate(t, 30, "root", nil, nil, true)
	other, otherKey, otherEncoded := newTestCertificate(t, 31, "untrusted root", nil, nil, true)

	var hits atomic.Int32

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)

		w.WriteHeader(http.StatusNotFound)
	}))

	t.Cleanup(server.Close)

	distribution := func(template *x509.Certificate) {
		template.CRLDistributionPoints = []string{server.URL}
		template.OCSPServer = []string{server.URL}
		template.IssuingCertificateURL = []string{server.URL}
	}

	untrustedInter, untrustedInterKey, untrustedInterEncoded := newTestCertificate(t, 32, "untrusted intermediate", other, otherKey, true, distribution)
	_, _, untrustedLeaf := newTestCertificate(t, 33, "untrusted leaf", untrustedInter, untrustedInterKey, false, distribution)

	valid, err := validateChain(rootEncoded, []any{untrustedLeaf, untrustedInterEncoded, otherEncoded}, false)

	assert.False(t, valid)
	assert.Error(t, err)
	assert.Zero(t, hits.Load())
}

func TestValidateChainLeafIsRoot(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 40, "root", nil, nil, true)
	_, _, interEncoded := newTestCertificate(t, 41, "intermediate", root, rootKey, true)

	var (
		valid bool
		err   error
	)

	require.NotPanics(t, func() {
		valid, err = validateChain(rootEncoded, []any{rootEncoded, interEncoded}, false)
	})

	assert.True(t, valid)
	assert.NoError(t, err)
}

func TestValidateChainRevocationRequiresChainIssuer(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 50, "root", nil, nil, true)
	inter, interKey, interEncoded := newTestCertificate(t, 51, "intermediate", root, rootKey, true)

	// The impostor has the subject of the intermediate but a different key.
	impostor, impostorKey, _ := newTestCertificate(t, 52, "intermediate", nil, nil, true)

	impostorCRL := newRevocationListServer(t, impostor, impostorKey, 53)
	impostorEmptyCRL := newRevocationListServer(t, impostor, impostorKey)
	rootCRL := newRevocationListServer(t, root, rootKey, 55)

	var hits atomic.Int32

	issuers := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)

		_, _ = w.Write(impostor.Raw)
	}))

	t.Cleanup(issuers.Close)

	distribution := func(uri string) func(template *x509.Certificate) {
		return func(template *x509.Certificate) {
			template.CRLDistributionPoints = []string{uri}
			template.IssuingCertificateURL = []string{issuers.URL}
		}
	}

	_, _, leafListed := newTestCertificate(t, 53, "leaf listed", inter, interKey, false, distribution(impostorCRL.URL))
	_, _, leafUnlisted := newTestCertificate(t, 54, "leaf unlisted", inter, interKey, false, distribution(impostorEmptyCRL.URL))
	_, _, leafListedByRoot := newTestCertificate(t, 55, "leaf listed by root", inter, interKey, false, distribution(rootCRL.URL))

	testCases := []struct {
		name     string
		chain    []any
		hardfail bool
		valid    bool
		err      error
	}{
		{
			name:  "ShouldNotTrustRevocationFromImpostor",
			chain: []any{leafListed, interEncoded},
			valid: true,
		},
		{
			name:     "ShouldRejectRevocationFromImpostorWhenHardFail",
			chain:    []any{leafListed, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errCRLUnavailable,
		},
		{
			name:     "ShouldRejectNonRevocationFromImpostorWhenHardFail",
			chain:    []any{leafUnlisted, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errCRLUnavailable,
		},
		{
			name:  "ShouldNotTrustRevocationFromOtherChainCertificate",
			chain: []any{leafListedByRoot, interEncoded},
			valid: true,
		},
		{
			name:     "ShouldRejectRevocationFromOtherChainCertificateWhenHardFail",
			chain:    []any{leafListedByRoot, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errCRLUnavailable,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := validateChain(rootEncoded, tc.chain, tc.hardfail)

			assert.Equal(t, tc.valid, valid)

			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}

	assert.Zero(t, hits.Load())
}

func TestValidateChainRevocationReasonLimitedList(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 60, "root", nil, nil, true)
	inter, interKey, interEncoded := newTestCertificate(t, 61, "intermediate", root, rootKey, true)

	listedCRL := newRevocationListServerWithTemplate(t, inter, interKey, reasonLimitedCRL(t), 62)
	unlistedCRL := newRevocationListServerWithTemplate(t, inter, interKey, reasonLimitedCRL(t))

	_, _, leafListed := newTestCertificate(t, 62, "leaf listed", inter, interKey, false, distributionPoints(listedCRL.URL))
	_, _, leafUnlisted := newTestCertificate(t, 63, "leaf unlisted", inter, interKey, false, distributionPoints(unlistedCRL.URL))

	testCases := []struct {
		name     string
		chain    []any
		hardfail bool
		valid    bool
		err      error
	}{
		{
			name:  "ShouldRejectListedCertificate",
			chain: []any{leafListed, interEncoded},
			valid: false,
			err:   errLeafCertRevoked,
		},
		{
			name:     "ShouldRejectListedCertificateWhenHardFail",
			chain:    []any{leafListed, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errLeafCertRevoked,
		},
		{
			name:  "ShouldNotTreatUnlistedCertificateAsRevoked",
			chain: []any{leafUnlisted, interEncoded},
			valid: true,
		},
		{
			name:     "ShouldRejectUnlistedCertificateWhenHardFail",
			chain:    []any{leafUnlisted, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errCRLUnavailable,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := validateChain(rootEncoded, tc.chain, tc.hardfail)

			assert.Equal(t, tc.valid, valid)

			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateChainRevocationReissuedIssuer(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 70, "root", nil, nil, true)
	inter, interKey, _ := newTestCertificate(t, 71, "intermediate", root, rootKey, true)

	// The reissued intermediate has the subject and key of the intermediate which issued the leaves, but not its
	// subject key id, and is the only intermediate in the chain.
	reissued, reissuedEncoded := newTestReissuedCertificate(t, 72, inter, interKey, root, rootKey)

	require.NotEqual(t, inter.SubjectKeyId, reissued.SubjectKeyId)

	listedCRL := newRevocationListServer(t, inter, interKey, 73)
	unlistedCRL := newRevocationListServer(t, inter, interKey)

	leafListedCert, _, leafListed := newTestCertificate(t, 73, "leaf listed", inter, interKey, false, distributionPoints(listedCRL.URL))
	_, _, leafUnlisted := newTestCertificate(t, 74, "leaf unlisted", inter, interKey, false, distributionPoints(unlistedCRL.URL))

	require.Equal(t, inter.SubjectKeyId, leafListedCert.AuthorityKeyId)

	testCases := []struct {
		name     string
		chain    []any
		hardfail bool
		valid    bool
		err      error
	}{
		{
			name:  "ShouldRejectListedCertificate",
			chain: []any{leafListed, reissuedEncoded},
			valid: false,
			err:   errLeafCertRevoked,
		},
		{
			name:     "ShouldRejectListedCertificateWhenHardFail",
			chain:    []any{leafListed, reissuedEncoded},
			hardfail: true,
			valid:    false,
			err:      errLeafCertRevoked,
		},
		{
			name:  "ShouldAcceptUnlistedCertificate",
			chain: []any{leafUnlisted, reissuedEncoded},
			valid: true,
		},
		{
			name:     "ShouldAcceptUnlistedCertificateWhenHardFail",
			chain:    []any{leafUnlisted, reissuedEncoded},
			hardfail: true,
			valid:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := validateChain(rootEncoded, tc.chain, tc.hardfail)

			assert.Equal(t, tc.valid, valid)

			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateChainRevocationChecksEveryDistributionPoint(t *testing.T) {
	root, rootKey, rootEncoded := newTestCertificate(t, 80, "root", nil, nil, true)
	inter, interKey, interEncoded := newTestCertificate(t, 81, "intermediate", root, rootKey, true)

	emptyCRL := newRevocationListServer(t, inter, interKey)
	otherEmptyCRL := newRevocationListServer(t, inter, interKey)
	listedCRL := newRevocationListServer(t, inter, interKey, 82)

	_, _, leafListedBySecond := newTestCertificate(t, 82, "leaf listed by second", inter, interKey, false, distributionPoints(emptyCRL.URL, listedCRL.URL))
	_, _, leafListedByFirst := newTestCertificate(t, 82, "leaf listed by first", inter, interKey, false, distributionPoints(listedCRL.URL, emptyCRL.URL))
	_, _, leafUnlisted := newTestCertificate(t, 83, "leaf unlisted", inter, interKey, false, distributionPoints(emptyCRL.URL, otherEmptyCRL.URL))

	testCases := []struct {
		name     string
		chain    []any
		hardfail bool
		valid    bool
		err      error
	}{
		{
			name:  "ShouldRejectCertificateListedBySecond",
			chain: []any{leafListedBySecond, interEncoded},
			valid: false,
			err:   errLeafCertRevoked,
		},
		{
			name:     "ShouldRejectCertificateListedBySecondWhenHardFail",
			chain:    []any{leafListedBySecond, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errLeafCertRevoked,
		},
		{
			name:  "ShouldRejectCertificateListedByFirst",
			chain: []any{leafListedByFirst, interEncoded},
			valid: false,
			err:   errLeafCertRevoked,
		},
		{
			name:     "ShouldRejectCertificateListedByFirstWhenHardFail",
			chain:    []any{leafListedByFirst, interEncoded},
			hardfail: true,
			valid:    false,
			err:      errLeafCertRevoked,
		},
		{
			name:  "ShouldAcceptCertificateListedByNeither",
			chain: []any{leafUnlisted, interEncoded},
			valid: true,
		},
		{
			name:     "ShouldAcceptCertificateListedByNeitherWhenHardFail",
			chain:    []any{leafUnlisted, interEncoded},
			hardfail: true,
			valid:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := validateChain(rootEncoded, tc.chain, tc.hardfail)

			assert.Equal(t, tc.valid, valid)

			if tc.err != nil {
				assert.Equal(t, tc.err, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

type recordingReadCloser struct {
	io.Reader
	closed bool
}

func (r *recordingReadCloser) Close() error {
	r.closed = true

	return nil
}

func TestDecodeDoesNotCloseTheReader(t *testing.T) {
	decoder, err := NewDecoder()
	require.NoError(t, err)

	rc := &recordingReadCloser{Reader: strings.NewReader("not a jwt")}

	_, err = decoder.Decode(rc)
	require.Error(t, err)

	assert.False(t, rc.closed, "Decode must leave closing the reader to the caller")
}

func distributionPoints(uris ...string) func(template *x509.Certificate) {
	return func(template *x509.Certificate) {
		template.CRLDistributionPoints = uris
	}
}

func reasonLimitedCRL(t *testing.T) func(template *x509.RevocationList) {
	t.Helper()

	value, err := asn1.Marshal(struct {
		OnlySomeReasons asn1.BitString `asn1:"optional,tag:3"`
	}{
		OnlySomeReasons: asn1.BitString{Bytes: []byte{0x40}, BitLength: 2},
	})
	require.NoError(t, err)

	return func(template *x509.RevocationList) {
		template.ExtraExtensions = []pkix.Extension{{Id: asn1.ObjectIdentifier{2, 5, 29, 28}, Critical: true, Value: value}}
	}
}

func newTestReissuedCertificate(t *testing.T, serial int64, original *x509.Certificate, originalKey *ecdsa.PrivateKey, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) (cert *x509.Certificate, encoded string) {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber:          big.NewInt(serial),
		Subject:               original.Subject,
		SubjectKeyId:          []byte{0x72, 0x65, 0x69, 0x73, 0x73, 0x75, 0x65, 0x64},
		NotBefore:             original.NotBefore,
		NotAfter:              original.NotAfter,
		BasicConstraintsValid: true,
		IsCA:                  true,
		KeyUsage:              original.KeyUsage,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &originalKey.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err = x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert, base64.StdEncoding.EncodeToString(der)
}
