package metadata

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestHasBasicFull(t *testing.T) {
	testCases := []struct {
		name     string
		types    AuthenticatorAttestationTypes
		expected bool
	}{
		{
			name:     "ShouldReturnTrueForBasicFull",
			types:    AuthenticatorAttestationTypes{BasicFull},
			expected: true,
		},
		{
			name:     "ShouldReturnTrueForAttCA",
			types:    AuthenticatorAttestationTypes{AttCA},
			expected: true,
		},
		{
			name:     "ShouldReturnTrueForMixedWithBasicFull",
			types:    AuthenticatorAttestationTypes{BasicSurrogate, BasicFull},
			expected: true,
		},
		{
			name:     "ShouldReturnFalseForBasicSurrogate",
			types:    AuthenticatorAttestationTypes{BasicSurrogate},
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForNone",
			types:    AuthenticatorAttestationTypes{None},
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForEmpty",
			types:    AuthenticatorAttestationTypes{},
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForAnonCA",
			types:    AuthenticatorAttestationTypes{AnonCA},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.types.HasBasicFull())
		})
	}
}

func TestIsUndesiredAuthenticatorStatusSlice(t *testing.T) {
	testCases := []struct {
		name     string
		status   AuthenticatorStatus
		values   []AuthenticatorStatus
		expected bool
	}{
		{
			name:     "ShouldReturnTrueWhenPresent",
			status:   Revoked,
			values:   []AuthenticatorStatus{AttestationKeyCompromise, Revoked},
			expected: true,
		},
		{
			name:     "ShouldReturnFalseWhenAbsent",
			status:   FidoCertified,
			values:   []AuthenticatorStatus{AttestationKeyCompromise, Revoked},
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForEmptySlice",
			status:   Revoked,
			values:   nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsUndesiredAuthenticatorStatusSlice(tc.status, tc.values))
		})
	}
}

func TestIsUndesiredAuthenticatorStatusMap(t *testing.T) {
	testCases := []struct {
		name     string
		status   AuthenticatorStatus
		values   map[AuthenticatorStatus]bool
		expected bool
	}{
		{
			name:     "ShouldReturnTrueWhenPresent",
			status:   Revoked,
			values:   map[AuthenticatorStatus]bool{Revoked: true},
			expected: true,
		},
		{
			name:     "ShouldReturnFalseWhenAbsent",
			status:   FidoCertified,
			values:   map[AuthenticatorStatus]bool{Revoked: true},
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForEmptyMap",
			status:   Revoked,
			values:   map[AuthenticatorStatus]bool{},
			expected: false,
		},
		{
			name:     "ShouldReturnFalseForNilMap",
			status:   Revoked,
			values:   nil,
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsUndesiredAuthenticatorStatusMap(tc.status, tc.values))
		})
	}
}

func TestDefaultUndesiredAuthenticatorStatuses(t *testing.T) {
	result := DefaultUndesiredAuthenticatorStatuses()

	assert.Contains(t, result, AttestationKeyCompromise)
	assert.Contains(t, result, UserVerificationBypass)
	assert.Contains(t, result, UserKeyRemoteCompromise)
	assert.Contains(t, result, UserKeyPhysicalCompromise)
	assert.Contains(t, result, Revoked)
	assert.NotContains(t, result, FidoCertified)
	assert.NotContains(t, result, NotFidoCertified)

	result[0] = FidoCertified
	fresh := DefaultUndesiredAuthenticatorStatuses()
	assert.NotEqual(t, result[0], fresh[0])
}

func TestRealClock_Now(t *testing.T) {
	c := RealClock{}

	before := time.Now()
	now := c.Now()
	after := time.Now()

	assert.False(t, now.Before(before))
	assert.False(t, now.After(after))
}

func TestStatement_Verifier(t *testing.T) {
	rootKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	rootCert := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test Root"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	rootDER, err := x509.CreateCertificate(rand.Reader, rootCert, rootCert, &rootKey.PublicKey, rootKey)
	require.NoError(t, err)

	root, err := x509.ParseCertificate(rootDER)
	require.NoError(t, err)

	interKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	interCert := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Test Intermediate"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IsCA:         true,
		KeyUsage:     x509.KeyUsageCertSign,
	}

	interDER, err := x509.CreateCertificate(rand.Reader, interCert, rootCert, &interKey.PublicKey, rootKey)
	require.NoError(t, err)

	inter, err := x509.ParseCertificate(interDER)
	require.NoError(t, err)

	testCases := []struct {
		name             string
		statement        *Statement
		intermediates    []*x509.Certificate
		hasRoots         bool
		hasIntermediates bool
	}{
		{
			name: "ShouldReturnVerifierWithRootsOnly",
			statement: &Statement{
				AttestationRootCertificates: []*x509.Certificate{root},
			},
			intermediates:    nil,
			hasRoots:         true,
			hasIntermediates: false,
		},
		{
			name: "ShouldReturnVerifierWithRootsAndIntermediates",
			statement: &Statement{
				AttestationRootCertificates: []*x509.Certificate{root},
			},
			intermediates:    []*x509.Certificate{inter},
			hasRoots:         true,
			hasIntermediates: true,
		},
		{
			name: "ShouldReturnVerifierWithEmptyRoots",
			statement: &Statement{
				AttestationRootCertificates: nil,
			},
			intermediates:    nil,
			hasRoots:         false,
			hasIntermediates: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := tc.statement.Verifier(tc.intermediates)

			assert.NotNil(t, opts.Roots)

			if tc.hasIntermediates {
				assert.NotNil(t, opts.Intermediates)
			}
		})
	}
}

func TestMetadata_ToMap(t *testing.T) {
	id1 := uuid.New()
	id2 := uuid.New()

	testCases := []struct {
		name         string
		metadata     *Metadata
		expectedLen  int
		expectedKeys []uuid.UUID
	}{
		{
			name: "ShouldConvertEntriesToMap",
			metadata: &Metadata{
				Parsed: Parsed{
					Entries: []Entry{
						{AaGUID: id1, MetadataStatement: Statement{Description: "Device 1"}},
						{AaGUID: id2, MetadataStatement: Statement{Description: "Device 2"}},
					},
				},
			},
			expectedLen:  2,
			expectedKeys: []uuid.UUID{id1, id2},
		},
		{
			name: "ShouldSkipNilAAGUID",
			metadata: &Metadata{
				Parsed: Parsed{
					Entries: []Entry{
						{AaGUID: uuid.Nil, MetadataStatement: Statement{Description: "Zero AAGUID"}},
						{AaGUID: id1, MetadataStatement: Statement{Description: "Device 1"}},
					},
				},
			},
			expectedLen:  1,
			expectedKeys: []uuid.UUID{id1},
		},
		{
			name: "ShouldReturnEmptyMapForNoEntries",
			metadata: &Metadata{
				Parsed: Parsed{
					Entries: nil,
				},
			},
			expectedLen:  0,
			expectedKeys: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := tc.metadata.ToMap()

			assert.Len(t, result, tc.expectedLen)

			for _, key := range tc.expectedKeys {
				assert.Contains(t, result, key)
			}
		})
	}
}
