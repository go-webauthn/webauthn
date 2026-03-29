package memory

import (
	"context"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
)

func TestNew(t *testing.T) {
	id := uuid.New()

	entry := &metadata.Entry{
		AaGUID: id,
		MetadataStatement: metadata.Statement{
			Description: "Test Authenticator",
		},
	}

	testCases := []struct {
		name string
		opts []Option
		err  string
	}{
		{
			name: "ShouldSucceedWithMetadata",
			opts: []Option{WithMetadata(map[uuid.UUID]*metadata.Entry{id: entry})},
		},
		{
			name: "ShouldFailWithoutMetadata",
			opts: nil,
			err:  "memory metadata provider has not been initialized with metadata",
		},
		{
			name: "ShouldSucceedWithAllOptions",
			opts: []Option{
				WithMetadata(map[uuid.UUID]*metadata.Entry{id: entry}),
				WithValidateEntry(false),
				WithValidateEntryPermitZeroAAGUID(true),
				WithValidateTrustAnchor(false),
				WithValidateStatus(false),
				WithValidateAttestationTypes(false),
				WithStatusUndesired([]metadata.AuthenticatorStatus{metadata.Revoked}),
				WithStatusDesired([]metadata.AuthenticatorStatus{metadata.FidoCertified}),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := New(tc.opts...)

			if tc.err != "" {
				assert.Nil(t, provider)
				require.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, provider)
			}
		})
	}
}

func TestProvider_GetEntry(t *testing.T) {
	id := uuid.New()
	missing := uuid.New()

	entry := &metadata.Entry{
		AaGUID: id,
		MetadataStatement: metadata.Statement{
			Description: "Test Authenticator",
		},
	}

	provider, err := New(WithMetadata(map[uuid.UUID]*metadata.Entry{id: entry}))
	require.NoError(t, err)

	testCases := []struct {
		name     string
		aaguid   uuid.UUID
		expected *metadata.Entry
	}{
		{
			name:     "ShouldReturnEntryWhenExists",
			aaguid:   id,
			expected: entry,
		},
		{
			name:     "ShouldReturnNilWhenNotExists",
			aaguid:   missing,
			expected: nil,
		},
		{
			name:     "ShouldReturnNilForNilUUID",
			aaguid:   uuid.Nil,
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := provider.GetEntry(context.Background(), tc.aaguid)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestProvider_ConfigurationFlags(t *testing.T) {
	testCases := []struct {
		name                     string
		opts                     []Option
		expectedEntry            bool
		expectedPermitZero       bool
		expectedTrustAnchor      bool
		expectedStatus           bool
		expectedAttestationTypes bool
	}{
		{
			name: "ShouldReturnDefaultFlags",
			opts: []Option{
				WithMetadata(map[uuid.UUID]*metadata.Entry{}),
			},
			expectedEntry:            true,
			expectedPermitZero:       false,
			expectedTrustAnchor:      true,
			expectedStatus:           true,
			expectedAttestationTypes: true,
		},
		{
			name: "ShouldReturnCustomFlags",
			opts: []Option{
				WithMetadata(map[uuid.UUID]*metadata.Entry{}),
				WithValidateEntry(false),
				WithValidateEntryPermitZeroAAGUID(true),
				WithValidateTrustAnchor(false),
				WithValidateStatus(false),
				WithValidateAttestationTypes(false),
			},
			expectedEntry:            false,
			expectedPermitZero:       true,
			expectedTrustAnchor:      false,
			expectedStatus:           false,
			expectedAttestationTypes: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := New(tc.opts...)
			require.NoError(t, err)

			ctx := context.Background()

			assert.Equal(t, tc.expectedEntry, provider.GetValidateEntry(ctx))
			assert.Equal(t, tc.expectedPermitZero, provider.GetValidateEntryPermitZeroAAGUID(ctx))
			assert.Equal(t, tc.expectedTrustAnchor, provider.GetValidateTrustAnchor(ctx))
			assert.Equal(t, tc.expectedStatus, provider.GetValidateStatus(ctx))
			assert.Equal(t, tc.expectedAttestationTypes, provider.GetValidateAttestationTypes(ctx))
		})
	}
}

func TestProvider_ValidateStatusReports(t *testing.T) {
	testCases := []struct {
		name    string
		opts    []Option
		reports []metadata.StatusReport
		err     string
	}{
		{
			name: "ShouldPassWithNoUndesiredStatuses",
			opts: []Option{
				WithMetadata(map[uuid.UUID]*metadata.Entry{}),
				WithValidateStatus(true),
			},
			reports: []metadata.StatusReport{{Status: metadata.FidoCertified}},
		},
		{
			name: "ShouldFailWithUndesiredStatus",
			opts: []Option{
				WithMetadata(map[uuid.UUID]*metadata.Entry{}),
				WithValidateStatus(true),
				WithStatusUndesired([]metadata.AuthenticatorStatus{metadata.Revoked}),
			},
			reports: []metadata.StatusReport{{Status: metadata.Revoked}},
			err:     "The following undesired status reports were present: REVOKED",
		},
		{
			name: "ShouldPassWhenStatusValidationDisabled",
			opts: []Option{
				WithMetadata(map[uuid.UUID]*metadata.Entry{}),
				WithValidateStatus(false),
			},
			reports: []metadata.StatusReport{{Status: metadata.Revoked}},
		},
		{
			name: "ShouldFailWithDesiredStatusAbsent",
			opts: []Option{
				WithMetadata(map[uuid.UUID]*metadata.Entry{}),
				WithValidateStatus(true),
				WithStatusDesired([]metadata.AuthenticatorStatus{metadata.FidoCertified}),
				WithStatusUndesired(nil),
			},
			reports: []metadata.StatusReport{{Status: metadata.NotFidoCertified}},
			err:     "The following desired status reports were absent: FIDO_CERTIFIED",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := New(tc.opts...)
			require.NoError(t, err)

			err = provider.ValidateStatusReports(context.Background(), tc.reports)

			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestProvider_GetEntry_NilMDS(t *testing.T) {
	p := &Provider{}

	entry, err := p.GetEntry(context.Background(), uuid.New())
	assert.Nil(t, entry)
	require.EqualError(t, err, "metadata: not initialized")
}
