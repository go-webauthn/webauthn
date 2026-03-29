package protocol

import (
	"context"
	"fmt"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"go.uber.org/mock/gomock"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/testing/mocks"
)

func TestValidateMetadata(t *testing.T) {
	aaguid := uuid.MustParse("0865c31d-05dc-4fb1-adce-3227bfb19967")

	testCases := []struct {
		name              string
		setup             func(t *testing.T) metadata.Provider
		aaguid            uuid.UUID
		attestationType   string
		attestationFormat string
		x5cs              []any
		err               *Error
	}{
		{
			name:              "ShouldReturnNilForNilProvider",
			setup:             func(t *testing.T) metadata.Provider { return nil },
			attestationFormat: "packed",
		},
		{
			name:              "ShouldReturnNilForNoneFormat",
			setup:             func(t *testing.T) metadata.Provider { return mocks.NewMockMetadataProvider(gomock.NewController(t)) },
			attestationFormat: "none",
		},
		{
			name: "ShouldFailWhenGetEntryReturnsError",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("db error"))

				return mds
			},
			aaguid:            aaguid,
			attestationFormat: "packed",
			err:               &Error{Type: "invalid_metadata", Details: "", DevInfo: "Failed to validate authenticator metadata for Authenticator Attestation GUID '0865c31d-05dc-4fb1-adce-3227bfb19967'. Error occurred retrieving the metadata entry: db error"},
		},
		{
			name: "ShouldReturnNilWhenEntryNilAndValidationNotRequired",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
				mds.EXPECT().GetValidateEntry(gomock.Any()).Return(false)

				return mds
			},
			aaguid:            aaguid,
			attestationFormat: "packed",
		},
		{
			name: "ShouldFailWhenEntryNilAndValidationRequired",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
				mds.EXPECT().GetValidateEntry(gomock.Any()).Return(true)

				return mds
			},
			aaguid:            aaguid,
			attestationFormat: "packed",
			err:               &Error{Type: "invalid_metadata", Details: "", DevInfo: "Failed to validate authenticator metadata for Authenticator Attestation GUID '0865c31d-05dc-4fb1-adce-3227bfb19967'. The authenticator has no registered metadata."},
		},
		{
			name: "ShouldReturnNilForZeroAAGUIDWhenPermitted",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
				mds.EXPECT().GetValidateEntryPermitZeroAAGUID(gomock.Any()).Return(true)

				return mds
			},
			aaguid:            uuid.Nil,
			attestationFormat: "packed",
		},
		{
			name: "ShouldFailWhenAttestationTypeMismatch",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				entry := &metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
					},
				}
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(entry, nil)
				mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(true)

				return mds
			},
			aaguid:            aaguid,
			attestationType:   "wrong-type",
			attestationFormat: "packed",
			err:               &Error{Type: "invalid_metadata", Details: "", DevInfo: "Failed to validate authenticator metadata for Authenticator Attestation GUID '0865c31d-05dc-4fb1-adce-3227bfb19967'. The attestation type 'wrong-type' is not known to be used by this authenticator."},
		},
		{
			name: "ShouldFailWhenStatusValidationFails",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				entry := &metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
					},
					StatusReports: []metadata.StatusReport{{Status: metadata.Revoked}},
				}
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(entry, nil)
				mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(false)
				mds.EXPECT().GetValidateStatus(gomock.Any()).Return(true)
				mds.EXPECT().ValidateStatusReports(gomock.Any(), gomock.Any()).Return(fmt.Errorf("revoked"))

				return mds
			},
			aaguid:            aaguid,
			attestationType:   string(metadata.BasicFull),
			attestationFormat: "packed",
			err:               &Error{Type: "invalid_metadata", Details: "", DevInfo: "Failed to validate authenticator metadata for Authenticator Attestation GUID '0865c31d-05dc-4fb1-adce-3227bfb19967'. Error occurred validating the authenticator status: revoked"},
		},
		{
			name: "ShouldReturnNilWhenTrustAnchorValidationWithNoX5Cs",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				entry := &metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
					},
				}
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(entry, nil)
				mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(false)
				mds.EXPECT().GetValidateStatus(gomock.Any()).Return(false)
				mds.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(true)

				return mds
			},
			aaguid:            aaguid,
			attestationType:   string(metadata.BasicFull),
			attestationFormat: "packed",
			x5cs:              nil,
		},
		{
			name: "ShouldFailWhenX5CNotBytes",
			setup: func(t *testing.T) metadata.Provider {
				ctrl := gomock.NewController(t)
				mds := mocks.NewMockMetadataProvider(ctrl)
				entry := &metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
					},
				}
				mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(entry, nil)
				mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(false)
				mds.EXPECT().GetValidateStatus(gomock.Any()).Return(false)
				mds.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(true)

				return mds
			},
			aaguid:            aaguid,
			attestationType:   string(metadata.BasicFull),
			attestationFormat: "packed",
			x5cs:              []any{"not-bytes"},
			err:               &Error{Type: "invalid_metadata", Details: "Failed to parse attestation certificate from x5c during attestation validation for Authenticator Attestation GUID '0865c31d-05dc-4fb1-adce-3227bfb19967'.", DevInfo: "The 1st certificate in the attestation was type 'string' but '[]byte' was expected"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mds := tc.setup(t)

			assert.Equal(t, tc.err, ValidateMetadata(context.Background(), mds, tc.aaguid, tc.attestationType, tc.attestationFormat, tc.x5cs))
		})
	}
}

func TestLoopOrdinalNumber(t *testing.T) {
	testCases := []struct {
		name     string
		n        int
		expected string
	}{
		{
			name:     "ShouldReturn1st",
			n:        0,
			expected: "1st",
		},
		{
			name:     "ShouldReturn2nd",
			n:        1,
			expected: "2nd",
		},
		{
			name:     "ShouldReturn3rd",
			n:        2,
			expected: "3rd",
		},
		{
			name:     "ShouldReturn4th",
			n:        3,
			expected: "4th",
		},
		{
			name:     "ShouldReturn10th",
			n:        9,
			expected: "10th",
		},
		{
			name:     "ShouldReturn11th",
			n:        10,
			expected: "11th",
		},
		{
			name:     "ShouldReturn12th",
			n:        11,
			expected: "12th",
		},
		{
			name:     "ShouldReturn13th",
			n:        12,
			expected: "13th",
		},
		{
			name:     "ShouldReturn21st",
			n:        20,
			expected: "21st",
		},
		{
			name:     "ShouldReturn22nd",
			n:        21,
			expected: "22nd",
		},
		{
			name:     "ShouldReturn23rd",
			n:        22,
			expected: "23rd",
		},
		{
			name:     "ShouldReturn100th",
			n:        99,
			expected: "100th",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, loopOrdinalNumber(tc.n))
		})
	}
}
