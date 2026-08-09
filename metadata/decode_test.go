package metadata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

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
				valid, err := validateChain(ConformanceMDSRoot, tc.chain)

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
	// When x5c is absent the caller sets chain = []any{root}. The single-entry
	// root chain must be accepted so that no-x5c MDS blobs can still be parsed.
	valid, err := validateChain(ConformanceMDSRoot, []any{ConformanceMDSRoot})

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
			valid, err := validateChain(rootEncoded, tc.chain)

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

	entries := make([]x509.RevocationListEntry, len(revoked))

	for i, serial := range revoked {
		entries[i] = x509.RevocationListEntry{
			SerialNumber:   big.NewInt(serial),
			RevocationTime: time.Now().Add(-time.Hour),
		}
	}

	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    big.NewInt(1),
		ThisUpdate:                time.Now().Add(-time.Hour),
		NextUpdate:                time.Now().Add(time.Hour),
		RevokedCertificateEntries: entries,
	}, issuer, issuerKey)
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
	_, _, leafOK := newTestCertificate(t, 24, "leaf", inter, interKey, false)

	testCases := []struct {
		name  string
		chain []any
		valid bool
		err   error
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
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			valid, err := validateChain(rootEncoded, tc.chain)

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
