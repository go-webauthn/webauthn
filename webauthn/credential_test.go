package webauthn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"
	"go.uber.org/mock/gomock"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/testing/mocks"
)

func TestNewCredentialFlags(t *testing.T) {
	testCases := []struct {
		name                   string
		flags                  protocol.AuthenticatorFlags
		expectedUserPresent    bool
		expectedUserVerified   bool
		expectedBackupEligible bool
		expectedBackupState    bool
	}{
		{
			name:                   "ShouldHandleNoFlags",
			flags:                  0,
			expectedUserPresent:    false,
			expectedUserVerified:   false,
			expectedBackupEligible: false,
			expectedBackupState:    false,
		},
		{
			name:                   "ShouldHandleAllFlags",
			flags:                  protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState,
			expectedUserPresent:    true,
			expectedUserVerified:   true,
			expectedBackupEligible: true,
			expectedBackupState:    true,
		},
		{
			name:                   "ShouldHandleUserPresentOnly",
			flags:                  protocol.FlagUserPresent,
			expectedUserPresent:    true,
			expectedUserVerified:   false,
			expectedBackupEligible: false,
			expectedBackupState:    false,
		},
		{
			name:                   "ShouldHandleBackupFlags",
			flags:                  protocol.FlagBackupEligible | protocol.FlagBackupState,
			expectedUserPresent:    false,
			expectedUserVerified:   false,
			expectedBackupEligible: true,
			expectedBackupState:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := NewCredentialFlags(tc.flags)

			assert.Equal(t, tc.expectedUserPresent, result.UserPresent)
			assert.Equal(t, tc.expectedUserVerified, result.UserVerified)
			assert.Equal(t, tc.expectedBackupEligible, result.BackupEligible)
			assert.Equal(t, tc.expectedBackupState, result.BackupState)
			assert.Equal(t, tc.flags, result.ProtocolValue())
		})
	}
}

func TestCredential_Verify(t *testing.T) {
	assert.EqualError(t, (&Credential{}).Verify(nil), "error verifying credential: the metadata provider must be provided but it's nil")

	testCases := []struct {
		name       string
		credential func(t *testing.T) Credential
		setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
		err        string
	}{
		{
			name: "ShouldFailParseError",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return Credential{
					Attestation: CredentialAttestation{
						ClientDataJSON: []byte(`{}`),
						Object:         []byte("not-valid-cbor"),
					},
				}
			},
			err: "error verifying credential: error parsing attestation: Error parsing the authenticator response",
		},
		{
			name: "ShouldVerifyNoneFormatWithClientDataHash",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromNoneAttestation(t)
			},
		},
		{
			name: "ShouldVerifyNoneFormatWithEmptyClientDataHash",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromNoneAttestation(t)
				credential.Attestation.ClientDataHash = nil

				return credential
			},
		},
		{
			name: "ShouldVerifyNoneFormatWithTransports",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromNoneAttestation(t)
				credential.Transport = []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC}

				return credential
			},
		},
		{
			name: "ShouldVerifyPackedFormatWithMetadataValidation",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromPackedAttestation(t)
			},
			setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
				t.Helper()

				provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(&metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
					},
				}, nil)
				provider.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(false)
				provider.EXPECT().GetValidateStatus(gomock.Any()).Return(false)
				provider.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(false)
			},
		},
		{
			name: "ShouldFailPackedFormatMetadataGetEntryError",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromPackedAttestation(t)
			},
			setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
				t.Helper()

				provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("entry lookup failed"))
			},
			err: "error verifying credential: error verifying attestation: Failed to validate authenticator metadata for Authenticator Attestation GUID '2369d4d0-13ce-48cb-9f26-f7ed8c9a6068'. Error occurred retrieving the metadata entry: entry lookup failed",
		},
		{
			name: "ShouldFailPackedFormatMetadataValidateStatus",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromPackedAttestation(t)
			},
			setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
				t.Helper()

				provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(&metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
					},
				}, nil)
				provider.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(false)
				provider.EXPECT().GetValidateStatus(gomock.Any()).Return(true)
				provider.EXPECT().ValidateStatusReports(gomock.Any(), gomock.Any()).Return(fmt.Errorf("status report invalid"))
			},
			err: "error verifying credential: error verifying attestation: Failed to validate authenticator metadata for Authenticator Attestation GUID '2369d4d0-13ce-48cb-9f26-f7ed8c9a6068'. Error occurred validating the authenticator status: status report invalid",
		},
		{
			name: "ShouldVerifyPackedFormatMetadataEntryNilNoValidation",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromPackedAttestation(t)
			},
			setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
				t.Helper()

				provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
				provider.EXPECT().GetValidateEntry(gomock.Any()).Return(false)
			},
		},
		{
			name: "ShouldFailPackedFormatMetadataEntryNilValidateEntryRequired",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromPackedAttestation(t)
			},
			setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
				t.Helper()

				provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
				provider.EXPECT().GetValidateEntry(gomock.Any()).Return(true)
			},
			err: "error verifying credential: error verifying attestation: Failed to validate authenticator metadata for Authenticator Attestation GUID '2369d4d0-13ce-48cb-9f26-f7ed8c9a6068'. The authenticator has no registered metadata.",
		},
		{
			name: "ShouldVerifyPackedFormatWithAttestationTypeValidation",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromPackedAttestation(t)
			},
			setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
				t.Helper()

				provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(&metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
					},
				}, nil)
				provider.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(true)
				provider.EXPECT().GetValidateStatus(gomock.Any()).Return(false)
				provider.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(false)
			},
		},
		{
			name: "ShouldFailPackedFormatAttestationTypeMismatch",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return testCredentialFromPackedAttestation(t)
			},
			setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
				t.Helper()

				provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(&metadata.Entry{
					MetadataStatement: metadata.Statement{
						AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicSurrogate},
					},
				}, nil)
				provider.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(true)
			},
			err: "error verifying credential: error verifying attestation: Failed to validate authenticator metadata for Authenticator Attestation GUID '2369d4d0-13ce-48cb-9f26-f7ed8c9a6068'. The attestation type 'basic_full' is not known to be used by this authenticator.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctrl := gomock.NewController(t)

			provider := mocks.NewMockMetadataProvider(ctrl)

			if tc.setup != nil {
				tc.setup(t, provider)
			}

			credential := tc.credential(t)

			err := credential.Verify(provider)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestCredential_Verify_RestoresAttestationType(t *testing.T) {
	credential := testCredentialFromNoneAttestation(t)
	credential.AttestationType = ""
	credential.AttestationFormat = "none"

	ctrl := gomock.NewController(t)
	provider := mocks.NewMockMetadataProvider(ctrl)

	require.NoError(t, credential.Verify(provider))
	assert.Equal(t, "none", credential.AttestationType)
	assert.Equal(t, "none", credential.AttestationFormat)
}

func TestCredential_Verify_LeavesExistingAttestationTypeAlone(t *testing.T) {
	// The self-heal must not overwrite a caller-supplied AttestationType. If the field is already populated,
	// Verify leaves it alone.
	credential := testCredentialFromNoneAttestation(t)
	credential.AttestationType = "caller-set-value"

	ctrl := gomock.NewController(t)
	provider := mocks.NewMockMetadataProvider(ctrl)

	require.NoError(t, credential.Verify(provider))
	assert.Equal(t, "caller-set-value", credential.AttestationType)
}

func TestCredential_Verify_RejectsTamperedPublicKey(t *testing.T) {
	t.Run("MismatchReturnsError", func(t *testing.T) {
		credential := testCredentialFromNoneAttestation(t)

		tampered := make([]byte, len(credential.PublicKey))
		copy(tampered, credential.PublicKey)
		tampered[0] ^= 0xFF
		credential.PublicKey = tampered

		ctrl := gomock.NewController(t)
		provider := mocks.NewMockMetadataProvider(ctrl)

		err := credential.Verify(provider)
		assert.EqualError(t, err, "error verifying credential: stored public key does not match the credential public key embedded in the attestation object")
	})

	t.Run("EmptyPublicKeyReturnsError", func(t *testing.T) {
		credential := testCredentialFromNoneAttestation(t)
		credential.PublicKey = nil

		ctrl := gomock.NewController(t)
		provider := mocks.NewMockMetadataProvider(ctrl)

		err := credential.Verify(provider)
		assert.EqualError(t, err, "error verifying credential: stored public key does not match the credential public key embedded in the attestation object")
	})
}

func TestCredential_VerifyAttestationType(t *testing.T) {
	testCases := []struct {
		name                    string
		credential              func(t *testing.T) Credential
		err                     string
		expectedAttestationType string
	}{
		{
			name: "ShouldNoOpWhenAttestationTypeAlreadySet",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromNoneAttestation(t)
				credential.AttestationType = "caller-set-value"
				credential.Attestation.Object = []byte("not-valid-cbor")

				return credential
			},
			expectedAttestationType: "caller-set-value",
		},
		{
			name: "ShouldRestoreNoneAttestationType",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromNoneAttestation(t)
				credential.AttestationType = ""

				return credential
			},
			expectedAttestationType: "none",
		},
		{
			name: "ShouldRestorePackedAttestationType",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromPackedAttestation(t)
				credential.AttestationType = ""

				return credential
			},
			expectedAttestationType: string(metadata.BasicFull),
		},
		{
			name: "ShouldRecomputeClientDataHashWhenEmpty",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromNoneAttestation(t)
				credential.AttestationType = ""
				credential.Attestation.ClientDataHash = nil

				return credential
			},
			expectedAttestationType: "none",
		},
		{
			name: "ShouldFailParseError",
			credential: func(t *testing.T) Credential {
				t.Helper()

				return Credential{
					Attestation: CredentialAttestation{
						ClientDataJSON: []byte(`{}`),
						Object:         []byte("not-valid-cbor"),
					},
				}
			},
			err: "error verifying credential: error parsing attestation: Error parsing the authenticator response",
		},
		{
			name: "ShouldFailMismatchedPublicKey",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromNoneAttestation(t)
				credential.AttestationType = ""

				tampered := make([]byte, len(credential.PublicKey))
				copy(tampered, credential.PublicKey)
				tampered[0] ^= 0xFF
				credential.PublicKey = tampered

				return credential
			},
			err: "error verifying credential: stored public key does not match the credential public key embedded in the attestation object",
		},
		{
			name: "ShouldFailEmptyPublicKey",
			credential: func(t *testing.T) Credential {
				t.Helper()

				credential := testCredentialFromNoneAttestation(t)
				credential.AttestationType = ""
				credential.PublicKey = nil

				return credential
			},
			err: "error verifying credential: stored public key does not match the credential public key embedded in the attestation object",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			credential := tc.credential(t)

			err := credential.VerifyAttestationType()

			if tc.err == "" {
				require.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}

			assert.Equal(t, tc.expectedAttestationType, credential.AttestationType)
		})
	}
}

// testCredentialFromNoneAttestation constructs a Credential with valid "none" format attestation data for testing.
func testCredentialFromNoneAttestation(t *testing.T) Credential {
	t.Helper()

	attObject, err := base64.RawURLEncoding.DecodeString("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	require.NoError(t, err)

	clientDataJSON, err := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ")
	require.NoError(t, err)

	clientDataHash := sha256.Sum256(clientDataJSON)

	parsed := (&protocol.AuthenticatorAttestationResponse{
		AuthenticatorResponse: protocol.AuthenticatorResponse{ClientDataJSON: clientDataJSON},
		AttestationObject:     attObject,
	})

	parsedResponse, err := parsed.Parse()
	require.NoError(t, err)

	return Credential{
		ID:              []byte("credential-id"),
		PublicKey:       parsedResponse.AttestationObject.AuthData.AttData.CredentialPublicKey,
		AttestationType: "none",
		Attestation: CredentialAttestation{
			ClientDataJSON: clientDataJSON,
			ClientDataHash: clientDataHash[:],
			Object:         attObject,
		},
	}
}

func TestNewCredential(t *testing.T) {
	testCases := []struct {
		name           string
		clientDataHash []byte
		parsed         *protocol.ParsedCredentialCreationData
		expected       *Credential
	}{
		{
			name:           "ShouldCreateCredential",
			clientDataHash: []byte("client-data-hash"),
			parsed: &protocol.ParsedCredentialCreationData{
				ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
					AuthenticatorAttachment: protocol.Platform,
				},
				Response: protocol.ParsedAttestationResponse{
					AttestationObject: protocol.AttestationObject{
						Format: "packed",
						Type:   string(metadata.BasicFull),
						AuthData: protocol.AuthenticatorData{
							Counter: 1,
							Flags:   protocol.FlagUserPresent | protocol.FlagUserVerified,
							AttData: protocol.AttestedCredentialData{
								AAGUID:              []byte("aaguid-value-here"),
								CredentialID:        []byte("credential-id"),
								CredentialPublicKey: []byte("public-key"),
							},
						},
					},
					Transports: []protocol.AuthenticatorTransport{protocol.USB},
				},
				Raw: protocol.CredentialCreationResponse{
					AttestationResponse: protocol.AuthenticatorAttestationResponse{
						AuthenticatorResponse: protocol.AuthenticatorResponse{
							ClientDataJSON: []byte("client-data-json"),
						},
						AuthenticatorData:  []byte("auth-data"),
						PublicKeyAlgorithm: -7,
						AttestationObject:  []byte("attestation-object"),
					},
				},
			},
			expected: &Credential{
				ID:                []byte("credential-id"),
				PublicKey:         []byte("public-key"),
				AttestationType:   string(metadata.BasicFull),
				AttestationFormat: "packed",
				Transport:         []protocol.AuthenticatorTransport{protocol.USB},
				Flags:             NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified),
				Authenticator: Authenticator{
					AAGUID:     []byte("aaguid-value-here"),
					SignCount:  1,
					Attachment: protocol.Platform,
				},
				Attestation: CredentialAttestation{
					ClientDataJSON:     []byte("client-data-json"),
					ClientDataHash:     []byte("client-data-hash"),
					AuthenticatorData:  []byte("auth-data"),
					PublicKeyAlgorithm: -7,
					Object:             []byte("attestation-object"),
				},
			},
		},
		{
			name:           "ShouldCreateCredentialWithNilHash",
			clientDataHash: nil,
			parsed: &protocol.ParsedCredentialCreationData{
				Response: protocol.ParsedAttestationResponse{
					AttestationObject: protocol.AttestationObject{
						Format: "none",
						Type:   string(metadata.None),
						AuthData: protocol.AuthenticatorData{
							AttData: protocol.AttestedCredentialData{
								CredentialID:        []byte("cred-2"),
								CredentialPublicKey: []byte("pub-2"),
							},
						},
					},
				},
				Raw: protocol.CredentialCreationResponse{},
			},
			expected: &Credential{
				ID:                []byte("cred-2"),
				PublicKey:         []byte("pub-2"),
				AttestationType:   string(metadata.None),
				AttestationFormat: "none",
				Flags:             CredentialFlags{},
				Authenticator:     Authenticator{},
				Attestation:       CredentialAttestation{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NewCredential(tc.clientDataHash, tc.parsed)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
		})
	}
}

func TestCredential_SignalUnknownCredential(t *testing.T) {
	testCases := []struct {
		name         string
		rpid         string
		have         *Credential
		expected     *protocol.SignalUnknownCredential
		expectedJSON string
	}{
		{
			"ShouldHandleStandard",
			"example.com",
			&Credential{
				ID: []byte("1234"),
			},
			&protocol.SignalUnknownCredential{
				CredentialID: protocol.URLEncodedBase64("1234"),
				RPID:         "example.com",
			},
			`{"credentialId":"MTIzNA","rpId":"example.com"}`,
		},
		{
			"ShouldHandleNoID",
			"example.com",
			&Credential{},
			&protocol.SignalUnknownCredential{
				RPID: "example.com",
			},
			`{"credentialId":null,"rpId":"example.com"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.SignalUnknownCredential(tc.rpid)

			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}

func TestCredentials_CredentialDescriptors(t *testing.T) {
	testCases := []struct {
		name         string
		have         Credentials
		expected     []protocol.CredentialDescriptor
		expectedJSON string
	}{
		{
			"ShouldHandleStandard",
			Credentials{
				Credential{
					ID: []byte("1234"),
				},
			},
			[]protocol.CredentialDescriptor{
				{
					Type:         protocol.PublicKeyCredentialType,
					CredentialID: protocol.URLEncodedBase64("1234"),
				},
			},
			`[{"type":"public-key","id":"MTIzNA"}]`,
		},
		{
			"ShouldHandleEmpty",
			Credentials{},
			[]protocol.CredentialDescriptor{},
			`[]`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.CredentialDescriptors()

			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}

func TestCredential_UnmarshalJSON(t *testing.T) {
	testCases := []struct {
		name              string
		input             string
		attestationType   string
		attestationFormat string
	}{
		{
			name:              "ShouldMigrateLegacyRecordWithPackedFormat",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"packed"}`,
			attestationType:   "",
			attestationFormat: "packed",
		},
		{
			name:              "ShouldMigrateLegacyRecordWithNoneFormat",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"none"}`,
			attestationType:   "",
			attestationFormat: "none",
		},
		{
			name:              "ShouldMigrateLegacyRecordWithFIDOU2FFormat",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"fido-u2f"}`,
			attestationType:   "",
			attestationFormat: "fido-u2f",
		},
		{
			name:              "ShouldMigrateLegacyRecordWithAndroidKeyFormat",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"android-key"}`,
			attestationType:   "",
			attestationFormat: "android-key",
		},
		{
			name:              "ShouldPreserveNewRecordWithBothFields",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"basic_full","attestationFormat":"packed"}`,
			attestationType:   "basic_full",
			attestationFormat: "packed",
		},
		{
			name:              "ShouldPreserveNewRecordWithSurrogate",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"basic_surrogate","attestationFormat":"packed"}`,
			attestationType:   "basic_surrogate",
			attestationFormat: "packed",
		},
		{
			name:              "ShouldPreserveTypeValueThatIsNotAFormat",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"basic_full"}`,
			attestationType:   "basic_full",
			attestationFormat: "",
		},
		{
			name:              "ShouldHandleEmptyBothFields",
			input:             `{"id":"MTIz","publicKey":"YWJj"}`,
			attestationType:   "",
			attestationFormat: "",
		},
		{
			name:              "ShouldHandleUnknownTypeString",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"something-unrecognised"}`,
			attestationType:   "something-unrecognised",
			attestationFormat: "",
		},
		{
			name:              "ShouldNotMigrateWhenFormatAlreadyPresent",
			input:             `{"id":"MTIz","publicKey":"YWJj","attestationType":"packed","attestationFormat":"tpm"}`,
			attestationType:   "packed",
			attestationFormat: "tpm",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var c Credential

			require.NoError(t, json.Unmarshal([]byte(tc.input), &c))
			assert.Equal(t, tc.attestationType, c.AttestationType)
			assert.Equal(t, tc.attestationFormat, c.AttestationFormat)
		})
	}

	t.Run("ShouldRejectMalformedJSON", func(t *testing.T) {
		var c Credential

		assert.Error(t, json.Unmarshal([]byte(`{not-json`), &c))
	})
}

func TestCredential_RoundTripJSON(t *testing.T) {
	// Marshal -> Unmarshal produces an equivalent record (no lossy migration applied to a record already carrying
	// both fields).
	original := Credential{
		ID:                []byte("cred-id"),
		AttestationType:   "basic_surrogate",
		AttestationFormat: "packed",
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var round Credential

	require.NoError(t, json.Unmarshal(data, &round))
	assert.Equal(t, original.AttestationType, round.AttestationType)
	assert.Equal(t, original.AttestationFormat, round.AttestationFormat)
}

func TestCredential_Descriptor_PopulatesBothFields(t *testing.T) {
	// Descriptor() mirrors Credential's attestation type / format split into the descriptor. The format field is
	// what GetAppID and the option helpers key on (against the "fido-u2f" format string); the type field carries
	// the real attestation type for completeness.
	c := Credential{
		ID:                []byte("cred-id"),
		AttestationType:   "basic_full",
		AttestationFormat: "fido-u2f",
	}

	descriptor := c.Descriptor()

	assert.Equal(t, protocol.PublicKeyCredentialType, descriptor.Type)
	assert.Equal(t, "basic_full", descriptor.AttestationType)
	assert.Equal(t, "fido-u2f", descriptor.AttestationFormat)
}

// testCredentialFromPackedAttestation constructs a Credential with valid "packed" format attestation data for testing.
func testCredentialFromPackedAttestation(t *testing.T) Credential {
	t.Helper()

	response := `{
		"id":"owBY6F5857tda9Pg5iFNCg6ksHpGOYhrNqIn46pkvhEMKIgNGcKS-vDGAUEroq0-VHnl1LhzQkPRQmYBTHjGcpLKZKSLa2m2ANI-91HjXzoJd_zFOiEnu7CDwQTff9KZ6uPlx7kUK-JJOHar-IyRKcNhc_kOJ2ezglmj1JYuIJLoDEyXlKkkviFdwk1vbWLnO3p_oWROUeIgH_S4CLVLPIJXkPe0YvMgp3ESs9CsrN6kvMTysVRIt_h5KUqpZo0TKCL96zwFk1X_2PwCLKWmOxVL35lJfUKOHG9rc3bmKlqZR6aOgZjerY6BpU8BTJkAqfOvdVlqFeEcywJQgveR7FOvnVtoqzd5oaEwjA",
		"rawId":"owBY6F5857tda9Pg5iFNCg6ksHpGOYhrNqIn46pkvhEMKIgNGcKS-vDGAUEroq0-VHnl1LhzQkPRQmYBTHjGcpLKZKSLa2m2ANI-91HjXzoJd_zFOiEnu7CDwQTff9KZ6uPlx7kUK-JJOHar-IyRKcNhc_kOJ2ezglmj1JYuIJLoDEyXlKkkviFdwk1vbWLnO3p_oWROUeIgH_S4CLVLPIJXkPe0YvMgp3ESs9CsrN6kvMTysVRIt_h5KUqpZo0TKCL96zwFk1X_2PwCLKWmOxVL35lJfUKOHG9rc3bmKlqZR6aOgZjerY6BpU8BTJkAqfOvdVlqFeEcywJQgveR7FOvnVtoqzd5oaEwjA",
		"response":{
			"attestationObject":"o2NmbXRmcGFja2VkZ2F0dFN0bXSjY2FsZyZjc2lnWEgwRgIhAIXRMqmC2_bHTkKUwOvLvmAikuQPCk__9clILwjhOz3VAiEApJXTrN4WMiPwFXqTIh0oI8AZBm3vs-y_UotbQFSnX99jeDVjgVkCqzCCAqcwggJMoAMCAQICFGqj6W3EVhRWQJPun0qqCMyTlnqKMAoGCCqGSM49BAMCMC0xETAPBgNVBAoMCFNvbG9LZXlzMQswCQYDVQQGEwJDSDELMAkGA1UEAwwCRjEwIBcNMjEwNTIzMDA1MjA2WhgPMjA3MTA1MTEwMDUyMDZaMIGDMQswCQYDVQQGEwJVUzERMA8GA1UECgwIU29sb0tleXMxIjAgBgNVBAsMGUF1dGhlbnRpY2F0b3IgQXR0ZXN0YXRpb24xPTA7BgNVBAMMNFNvbG8gMiBORkMrVVNCLUMgMjM2OUQ0RDAxM0NFNDhDQjlGMjZGN0VEOEM5QTYwNjggQjIwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAS6N5V2fT-agh34bRiW--Wl6CQPSsnLqqSEID0t5RRKjjl1NDI__mzuyYuOrWyb5yzGZRHgnHq65cm2ROpxo6AOo4HwMIHtMB0GA1UdDgQWBBQ6CEDC5W8_zAMOhVgV8wHJI8n3bzAfBgNVHSMEGDAWgBRBa7ZL76IZDeRiX_0pBJa5gim0-DAJBgNVHRMEAjAAMAsGA1UdDwQEAwIE8DAyBggrBgEFBQcBAQQmMCQwIgYIKwYBBQUHMAKGFmh0dHA6Ly9pLnMycGtpLm5ldC9mMS8wJwYDVR0fBCAwHjAcoBqgGIYWaHR0cDovL2MuczJwa2kubmV0L3IxLzAhBgsrBgEEAYLlHAEBBAQSBBAjadTQE85Iy58m9-2MmmBoMBMGCysGAQQBguUcAgEBBAQDAgQwMAoGCCqGSM49BAMCA0kAMEYCIQCP82Rolr0U2FvOJq53AZYcA6xfC4-cNDczvf0FtU1SQAIhAIvb21Z3D8RCvwk2-Ryn4wpsGnn2vma6Bw3E1f48hyVwaGF1dGhEYXRhWQFtarm78N-aFvkduzO7sTL6-dF8eCxIJsbscOzuWNl-9SpBAAAAJyNp1NATzkjLnyb37YyaYGgBDKMAWOhefOe7XWvT4OYhTQoOpLB6RjmIazaiJ-OqZL4RDCiIDRnCkvrwxgFBK6KtPlR55dS4c0JD0UJmAUx4xnKSymSki2tptgDSPvdR4186CXf8xTohJ7uwg8EE33_Smerj5ce5FCviSTh2q_iMkSnDYXP5Didns4JZo9SWLiCS6AxMl5SpJL4hXcJNb21i5zt6f6FkTlHiIB_0uAi1SzyCV5D3tGLzIKdxErPQrKzepLzE8rFUSLf4eSlKqWaNEygi_es8BZNV_9j8AiylpjsVS9-ZSX1Cjhxva3N25ipamUemjoGY3q2OgaVPAUyZAKnzr3VZahXhHMsCUIL3kexTr51baKs3eaGhMIykAQEDJyAGIVggjz9UkJ7cKooE3blSuzlqxkdLppMuFl3CIiST8odWS6k",
			"clientDataJSON":"eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiQ1dieENUMEc0TDJ5T1JwQkw2U1dWaWd3ZTJrUUVYQmhvNUw2d0U0Ny1FcyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uZmlyc3R5ZWFyLmlkLmF1IiwiY3Jvc3NPcmlnaW4iOmZhbHNlfQ"
		},
	"type":"public-key"
	}`

	var ccr protocol.CredentialCreationResponse

	require.NoError(t, json.Unmarshal([]byte(response), &ccr))

	parsed, err := ccr.AttestationResponse.Parse()
	require.NoError(t, err)

	clientDataHash := sha256.Sum256(ccr.AttestationResponse.ClientDataJSON)

	return Credential{
		ID:              ccr.RawID,
		PublicKey:       parsed.AttestationObject.AuthData.AttData.CredentialPublicKey,
		AttestationType: "packed",
		Authenticator: Authenticator{
			AAGUID: parsed.AttestationObject.AuthData.AttData.AAGUID,
		},
		Attestation: CredentialAttestation{
			ClientDataJSON: ccr.AttestationResponse.ClientDataJSON,
			ClientDataHash: clientDataHash[:],
			Object:         ccr.AttestationResponse.AttestationObject,
		},
	}
}

func TestCredential_MsgpRoundTrip(t *testing.T) {
	// Exercises the Marshal/Unmarshal and Encode/Decode paths of every top-level field branch on Credential,
	// including the Transport slice element, the CredentialFlags shim, and the nested Authenticator /
	// CredentialAttestation structs. The generated TestMarshalUnmarshalCredential only covers the zero value.
	original := newPopulatedCredential()

	t.Run("MarshalUnmarshalPreservesFields", func(t *testing.T) {
		data, err := original.MarshalMsg(nil)
		require.NoError(t, err)

		var decoded Credential

		left, err := decoded.UnmarshalMsg(data)
		require.NoError(t, err)
		assert.Empty(t, left, "UnmarshalMsg should consume all bytes")
		assert.Equal(t, original, decoded)

		// Msgsize returns an upper-bound estimate; marshalled output must fit within it.
		assert.LessOrEqual(t, len(data), original.Msgsize())
	})

	t.Run("EncodeDecodePreservesFields", func(t *testing.T) {
		var buf bytes.Buffer

		err := msgp.Encode(&buf, &original)
		require.NoError(t, err)

		var decoded Credential

		require.NoError(t, msgp.Decode(&buf, &decoded))
		assert.Equal(t, original, decoded)
	})

	t.Run("UnmarshalSkipsUnknownKeysAlongsideKnown", func(t *testing.T) {
		data, err := original.MarshalMsg(nil)
		require.NoError(t, err)

		size, rest, err := msgp.ReadMapHeaderBytes(data)
		require.NoError(t, err)

		spliced := msgp.AppendMapHeader(nil, size+1)
		spliced = msgp.AppendString(spliced, "xyz")
		spliced = msgp.AppendBool(spliced, true)
		spliced = append(spliced, rest...)

		var decoded Credential

		left, err := decoded.UnmarshalMsg(spliced)
		require.NoError(t, err)
		assert.Empty(t, left)
		assert.Equal(t, original, decoded)
	})

	t.Run("UnmarshalSkipsUnknownKeysOnly", func(t *testing.T) {
		tiny := []byte{0x81, 0xa3, 'x', 'y', 'z', 0xc3}

		var decoded Credential

		left, err := decoded.UnmarshalMsg(tiny)
		require.NoError(t, err)
		assert.Empty(t, left)
		assert.Equal(t, Credential{}, decoded)
	})
}

func TestCredentialAttestation_MsgpRoundTrip(t *testing.T) {
	original := CredentialAttestation{
		ClientDataJSON:     []byte(`{"type":"webauthn.create"}`),
		ClientDataHash:     bytes.Repeat([]byte{0x01}, 32),
		AuthenticatorData:  []byte{0xff, 0xee, 0xdd},
		PublicKeyAlgorithm: -257,
		Object:             []byte{0xca, 0xfe, 0xba, 0xbe},
	}

	data, err := original.MarshalMsg(nil)
	require.NoError(t, err)

	var decoded CredentialAttestation

	left, err := decoded.UnmarshalMsg(data)
	require.NoError(t, err)
	assert.Empty(t, left)
	assert.Equal(t, original, decoded)
	assert.LessOrEqual(t, len(data), original.Msgsize())

	// EncodeMsg / DecodeMsg via msgp.Writer and msgp.Reader path.
	var buf bytes.Buffer

	require.NoError(t, msgp.Encode(&buf, &original))

	var streamDecoded CredentialAttestation

	require.NoError(t, msgp.Decode(&buf, &streamDecoded))
	assert.Equal(t, original, streamDecoded)
}

func TestCredentialFlags_MsgpRoundTrip(t *testing.T) {
	// The //msgp:shim directive makes CredentialFlags encode as a single msgpack byte via MsgpByte and decode via
	// CredentialFlagsFromMsgpByte. Generated code for CredentialFlags has the smallest surface of any msgp method
	// pair in this package and was 0%-covered before this test.
	testCases := []struct {
		name  string
		flags protocol.AuthenticatorFlags
	}{
		{"Zero", 0},
		{"UserPresent", protocol.FlagUserPresent},
		{"UserVerified", protocol.FlagUserVerified},
		{"AllKnownFlags", protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState},
		{"AllBitsSet", protocol.AuthenticatorFlags(0xFF)},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := NewCredentialFlags(tc.flags)

			data, err := original.MarshalMsg(nil)
			require.NoError(t, err)
			// msgpack encodes a byte as either a 1-byte positive fixint (values 0x00-0x7f) or a 2-byte uint 8
			// (0xcc + payload) for values ≥ 0x80; either is acceptable.
			assert.LessOrEqual(t, len(data), 2, "CredentialFlags should encode in at most 2 msgpack bytes")
			assert.GreaterOrEqual(t, len(data), 1)

			var decoded CredentialFlags

			left, err := decoded.UnmarshalMsg(data)
			require.NoError(t, err)
			assert.Empty(t, left)
			assert.Equal(t, original, decoded)
			assert.Equal(t, original.ProtocolValue(), decoded.ProtocolValue())

			// Stream path via msgp.Writer / msgp.Reader.
			var buf bytes.Buffer

			require.NoError(t, msgp.Encode(&buf, original))

			var streamDecoded CredentialFlags

			require.NoError(t, msgp.Decode(&buf, &streamDecoded))
			assert.Equal(t, original, streamDecoded)
		})
	}

	// Truncated-input error path.
	var decoded CredentialFlags

	_, err := decoded.UnmarshalMsg(nil)
	require.Error(t, err)
}

func TestCredentials_MsgpRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		original Credentials
	}{
		{"Empty", Credentials{}},
		{"Single", Credentials{newPopulatedCredential()}},
		{"Multiple", Credentials{newPopulatedCredential(), newPopulatedCredential(), newPopulatedCredential()}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.original.MarshalMsg(nil)
			require.NoError(t, err)

			var decoded Credentials

			left, err := decoded.UnmarshalMsg(data)
			require.NoError(t, err)
			assert.Empty(t, left)

			if len(tc.original) == 0 {
				assert.Empty(t, decoded)
			} else {
				assert.Equal(t, tc.original, decoded)
			}

			assert.LessOrEqual(t, len(data), tc.original.Msgsize())
		})
	}
}

func newPopulatedCredential() Credential {
	return Credential{
		ID:                []byte{0x01, 0x02, 0x03, 0x04},
		PublicKey:         []byte{0xa5, 0x01, 0x02, 0x03, 0x26},
		AttestationType:   "basic_full",
		AttestationFormat: "packed",
		Transport:         []protocol.AuthenticatorTransport{protocol.USB, protocol.NFC, protocol.Hybrid},
		Flags:             NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible),
		Authenticator: Authenticator{
			AAGUID:       bytes.Repeat([]byte{0x11}, 16),
			SignCount:    42,
			CloneWarning: true,
			Attachment:   protocol.Platform,
		},
		Attestation: CredentialAttestation{
			ClientDataJSON:     []byte(`{"type":"webauthn.create","challenge":"abc","origin":"https://example.com"}`),
			ClientDataHash:     bytes.Repeat([]byte{0xde}, 32),
			AuthenticatorData:  bytes.Repeat([]byte{0xaa}, 64),
			PublicKeyAlgorithm: -7,
			Object:             bytes.Repeat([]byte{0xbb}, 128),
		},
	}
}

func TestCredential_MsgpEncodeErrorPaths(t *testing.T) {
	v := newPopulatedCredential()

	data, err := v.MarshalMsg(nil)
	require.NoError(t, err)

	exerciseEncodeMsgErrorPaths(t, &v, data)
}

func TestCredentialAttestation_MsgpEncodeErrorPaths(t *testing.T) {
	v := CredentialAttestation{
		ClientDataJSON:     []byte(`{"type":"webauthn.create"}`),
		ClientDataHash:     bytes.Repeat([]byte{0x01}, 32),
		AuthenticatorData:  []byte{0xff, 0xee, 0xdd},
		PublicKeyAlgorithm: -257,
		Object:             []byte{0xca, 0xfe, 0xba, 0xbe},
	}

	data, err := v.MarshalMsg(nil)
	require.NoError(t, err)

	exerciseEncodeMsgErrorPaths(t, &v, data)
}

func TestCredentialFlags_MsgpEncodeErrorPaths(t *testing.T) {
	v := NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState)

	data, err := v.MarshalMsg(nil)
	require.NoError(t, err)

	exerciseEncodeMsgErrorPaths(t, v, data)
}

func TestCredentials_MsgpEncodeErrorPaths(t *testing.T) {
	v := Credentials{newPopulatedCredential(), newPopulatedCredential()}

	data, err := v.MarshalMsg(nil)
	require.NoError(t, err)

	exerciseEncodeMsgErrorPaths(t, v, data)
}

func TestCredential_DecodeMsgInvalidTypes(t *testing.T) {
	t.Run("NotAMap", func(t *testing.T) {
		var c Credential

		_, err := c.UnmarshalMsg(msgpString("not a map"))
		require.Error(t, err)

		var c2 Credential

		require.Error(t, msgp.Decode(bytes.NewReader(msgpString("not a map")), &c2))
	})

	testCases := []struct {
		name    string
		data    []byte
		wantSub string
	}{
		{"IDAsBool", msgpOneFieldMap("id", msgpBool(true)), "ID"},
		{"PublicKeyAsInt", msgpOneFieldMap("pk", msgpInt64(42)), "PublicKey"},
		{"AttestationTypeAsInt", msgpOneFieldMap("atttype", msgpInt64(42)), "AttestationType"},
		{"AttestationFormatAsBool", msgpOneFieldMap("attfmt", msgpBool(true)), "AttestationFormat"},
		{"TransportNotArray", msgpOneFieldMap("t", msgpBool(true)), "Transport"},
		{"TransportElementNotString", msgpOneFieldMap("t", func() []byte {
			b := msgp.AppendArrayHeader(nil, 1)

			return append(b, msgpBool(true)...)
		}()), "Transport"},
		{"FlagsAsString", msgpOneFieldMap("flg", msgpString("x")), "Flags"},
		{"AuthenticatorAsBool", msgpOneFieldMap("a", msgpBool(true)), "Authenticator"},
		{"AttestationAsBool", msgpOneFieldMap("att", msgpBool(true)), "Attestation"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var c Credential

			_, err := c.UnmarshalMsg(tc.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)

			var c2 Credential

			streamErr := msgp.Decode(bytes.NewReader(tc.data), &c2)
			require.Error(t, streamErr)
			assert.Contains(t, streamErr.Error(), tc.wantSub)
		})
	}
}

func TestCredentialAttestation_DecodeMsgInvalidTypes(t *testing.T) {
	t.Run("NotAMap", func(t *testing.T) {
		var c CredentialAttestation

		_, err := c.UnmarshalMsg(msgpString("not a map"))
		require.Error(t, err)

		var c2 CredentialAttestation

		require.Error(t, msgp.Decode(bytes.NewReader(msgpString("not a map")), &c2))
	})

	testCases := []struct {
		name    string
		data    []byte
		wantSub string
	}{
		{"ClientDataJSONAsInt", msgpOneFieldMap("cdj", msgpInt64(42)), "ClientDataJSON"},
		{"ClientDataHashAsBool", msgpOneFieldMap("cdh", msgpBool(true)), "ClientDataHash"},
		{"AuthenticatorDataAsInt", msgpOneFieldMap("data", msgpInt64(42)), "AuthenticatorData"},
		{"PublicKeyAlgorithmAsString", msgpOneFieldMap("alg", msgpString("x")), "PublicKeyAlgorithm"},
		{"ObjectAsBool", msgpOneFieldMap("obj", msgpBool(true)), "Object"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var c CredentialAttestation

			_, err := c.UnmarshalMsg(tc.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)

			var c2 CredentialAttestation

			streamErr := msgp.Decode(bytes.NewReader(tc.data), &c2)
			require.Error(t, streamErr)
			assert.Contains(t, streamErr.Error(), tc.wantSub)
		})
	}
}

func TestCredentialFlags_DecodeMsgInvalidTypes(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
	}{
		{"AsString", msgpString("x")},
		{"AsBool", msgpBool(true)},
		{"AsNil", msgp.AppendNil(nil)},
		{"Truncated", nil},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var f CredentialFlags

			_, err := f.UnmarshalMsg(tc.data)
			require.Error(t, err)

			if len(tc.data) > 0 {
				var f2 CredentialFlags

				require.Error(t, msgp.Decode(bytes.NewReader(tc.data), &f2))
			}
		})
	}
}

func TestCredentials_DecodeMsgInvalidTypes(t *testing.T) {
	t.Run("NotAnArray", func(t *testing.T) {
		var c Credentials

		_, err := c.UnmarshalMsg(msgpString("not an array"))
		require.Error(t, err)

		var c2 Credentials

		require.Error(t, msgp.Decode(bytes.NewReader(msgpString("not an array")), &c2))
	})

	t.Run("ElementNotAMap", func(t *testing.T) {
		b := msgp.AppendArrayHeader(nil, 1)
		b = append(b, msgpBool(true)...)

		var c Credentials

		_, err := c.UnmarshalMsg(b)
		require.Error(t, err)

		var c2 Credentials

		require.Error(t, msgp.Decode(bytes.NewReader(b), &c2))
	})
}

type failingWriter struct {
	limit int
	count int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.count
	if remaining <= 0 {
		return 0, errors.New("failingWriter: exhausted")
	}

	if len(p) > remaining {
		w.count = w.limit

		return remaining, errors.New("failingWriter: exhausted")
	}

	w.count += len(p)

	return len(p), nil
}

func exerciseEncodeMsgErrorPaths(t *testing.T, enc msgp.Encodable, marshalled []byte) {
	t.Helper()

	for limit := 0; limit <= len(marshalled); limit++ {
		fw := &failingWriter{limit: limit}
		wr := msgp.NewWriterSize(fw, 18)

		err := enc.EncodeMsg(wr)
		if err == nil {
			err = wr.Flush()
		}

		if limit < len(marshalled) {
			require.Errorf(t, err, "EncodeMsg should fail when underlying writer errors after %d bytes", limit)
		} else {
			require.NoError(t, err)
		}
	}
}

func msgpOneFieldMap(key string, value []byte) []byte {
	b := msgp.AppendMapHeader(nil, 1)
	b = msgp.AppendString(b, key)

	return append(b, value...)
}

func msgpBool(v bool) []byte     { return msgp.AppendBool(nil, v) }  //nolint:unparam
func msgpInt64(v int64) []byte   { return msgp.AppendInt64(nil, v) } //nolint:unparam
func msgpString(v string) []byte { return msgp.AppendString(nil, v) }
