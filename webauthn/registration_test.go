package webauthn

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"testing"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/testing/mocks"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"
)

func TestWithRegistrationRelyingPartyID(t *testing.T) {
	testCases := []struct {
		name         string
		have         *Config
		opts         []RegistrationOption
		expectedID   string
		expectedName string
		err          string
	}{
		{
			name: "OptionDefinedInConfig",
			have: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts:         nil,
			expectedID:   "example.com",
			expectedName: "Test Display Name",
		},
		{
			name: "OptionDefinedInConfigAndOpts",
			have: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts:         []RegistrationOption{WithRegistrationRelyingPartyID("a.example.com"), WithRegistrationRelyingPartyName("Test Display Name2")},
			expectedID:   "a.example.com",
			expectedName: "Test Display Name2",
		},
		{
			name: "OptionDefinedInConfigWithNoErrAndInOptsWithError",
			have: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts: []RegistrationOption{WithRegistrationRelyingPartyID("---::~!!~@#M!@OIK#N!@IOK@@@@@@@@@@"), WithRegistrationRelyingPartyName("Test Display Name2")},
			err:  "error generating credential creation: the relying party id failed to validate as it's not a valid domain string with error: parse \"---::~!!~@\": first path segment in URL cannot contain colon",
		},
		{
			name: "OptionDefinedInOpts",
			have: &Config{
				RPOrigins: []string{"example.com"},
			},
			opts:         []RegistrationOption{WithRegistrationRelyingPartyID("example.com"), WithRegistrationRelyingPartyName("Test Display Name")},
			expectedID:   "example.com",
			expectedName: "Test Display Name",
		},
		{
			name: "OptionDisplayNameNotDefined",
			have: &Config{
				RPOrigins: []string{"https://example.com"},
			},
			opts: []RegistrationOption{WithRegistrationRelyingPartyID("example.com")},
			err:  "error generating credential creation: the relying party display name must be provided via the configuration or a functional option for a creation",
		},
		{
			name: "OptionIDNotDefined",
			have: &Config{
				RPOrigins: []string{"https://example.com"},
			},
			opts: []RegistrationOption{WithRegistrationRelyingPartyName("Test Display Name")},
			err:  "error generating credential creation: the relying party id must be provided via the configuration or a functional option for a creation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.have)
			assert.NoError(t, err)

			user := &defaultUser{}

			creation, _, err := w.BeginRegistration(user, tc.opts...)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, creation)
				assert.Equal(t, tc.expectedID, creation.Response.RelyingParty.ID)
				assert.Equal(t, tc.expectedName, creation.Response.RelyingParty.Name)
			}
		})
	}
}

func TestRegistration_FinishRegistrationFailure(t *testing.T) {
	user := &defaultUser{
		id: []byte("123"),
	}

	session := SessionData{
		UserID: []byte("ABC"),
	}

	webauthn := &WebAuthn{}

	credential, err := webauthn.FinishRegistration(user, session, nil)
	if err == nil {
		t.Errorf("FinishRegistration() error = nil, want %v", protocol.ErrBadRequest.Type)
	}

	if credential != nil {
		t.Errorf("FinishRegistration() credential = %v, want nil", credential)
	}
}

func TestEntityEncoding(t *testing.T) {
	testCases := []struct {
		name           string
		b64            bool
		have, expected string
	}{
		{"ShouldEncodeBase64", true, "abc", `{"name":"","displayName":"","id":"YWJj"}`},
		{"ShouldEncodeString", false, "abc", `{"name":"","displayName":"","id":"abc"}`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entityUser := protocol.UserEntity{}

			if tc.b64 {
				entityUser.ID = protocol.URLEncodedBase64(tc.have)
			} else {
				entityUser.ID = tc.have
			}

			data, err := json.Marshal(entityUser)

			assert.NoError(t, err)

			assert.Equal(t, tc.expected, string(data))
		})
	}
}

func TestCreateCredential_Errors(t *testing.T) {
	testCases := []struct {
		name    string
		user    User
		session SessionData
		err     string
	}{
		{
			name: "ShouldFailUserIDMismatch",
			user: &defaultUser{
				id: []byte("123"),
			},
			session: SessionData{
				UserID: []byte("456"),
			},
			err: "ID mismatch for User and Session",
		},
		{
			name: "ShouldFailSessionExpired",
			user: &defaultUser{
				id: []byte("123"),
			},
			session: SessionData{
				UserID:  []byte("123"),
				Expires: time.Now().Add(-time.Hour),
			},
			err: "Session has Expired",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &WebAuthn{Config: &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
			}}

			credential, err := w.CreateCredential(tc.user, tc.session, nil)
			assert.Nil(t, credential)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestBeginRegistration_Timeouts(t *testing.T) {
	testCases := []struct {
		name            string
		config          *Config
		opts            []RegistrationOption
		expectedTimeout int
	}{
		{
			name: "ShouldUseDefaultTimeout",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			expectedTimeout: 300000,
		},
		{
			name: "ShouldUseUVDTimeout",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
				AuthenticatorSelection: protocol.AuthenticatorSelection{
					UserVerification: protocol.VerificationDiscouraged,
				},
			},
			expectedTimeout: 120000,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.config)
			require.NoError(t, err)

			user := &defaultUser{id: []byte("123")}

			creation, _, err := w.BeginRegistration(user, tc.opts...)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedTimeout, creation.Response.Timeout)
		})
	}
}

func TestBeginRegistration_EncodeUserIDAsString(t *testing.T) {
	testCases := []struct {
		name           string
		encodeAsString bool
		userID         string
		expectedIDType string
	}{
		{
			name:           "ShouldEncodeAsBase64",
			encodeAsString: false,
			userID:         "testuser",
			expectedIDType: "protocol.URLEncodedBase64",
		},
		{
			name:           "ShouldEncodeAsString",
			encodeAsString: true,
			userID:         "testuser",
			expectedIDType: "string",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				RPID:                 "example.com",
				RPDisplayName:        "Test Display Name",
				RPOrigins:            []string{"https://example.com"},
				EncodeUserIDAsString: tc.encodeAsString,
			}

			w, err := New(config)
			require.NoError(t, err)

			user := &defaultUser{id: []byte(tc.userID)}

			creation, _, err := w.BeginRegistration(user)
			require.NoError(t, err)

			if tc.encodeAsString {
				_, ok := creation.Response.User.ID.(string)
				assert.True(t, ok)
			} else {
				_, ok := creation.Response.User.ID.(protocol.URLEncodedBase64)
				assert.True(t, ok)
			}
		})
	}
}

func TestBeginMediatedRegistration_ChallengeLength(t *testing.T) {
	// withTestChallenge is a test-only RegistrationOption that overrides the generated challenge. It mirrors the
	// WithChallenge login option; no equivalent is exported for registration, so we synthesise one here to exercise
	// the minimum-length guard.
	withTestChallenge := func(challenge []byte) RegistrationOption {
		return func(cco *protocol.PublicKeyCredentialCreationOptions) {
			cco.Challenge = challenge
		}
	}

	config := &Config{
		RPID:          "example.com",
		RPDisplayName: "Test Display Name",
		RPOrigins:     []string{"https://example.com"},
	}

	testCases := []struct {
		name   string
		opts   []RegistrationOption
		expLen int
		err    string
	}{
		{
			name:   "ShouldSucceedWithDefaultChallenge",
			opts:   nil,
			expLen: 32,
		},
		{
			name: "ShouldFailNilChallenge",
			opts: []RegistrationOption{withTestChallenge(nil)},
			err:  "error generating credential creation: the challenge must be at least 16 bytes",
		},
		{
			name: "ShouldFailEmptyChallenge",
			opts: []RegistrationOption{withTestChallenge([]byte{})},
			err:  "error generating credential creation: the challenge must be at least 16 bytes",
		},
		{
			name: "ShouldFailEightByteChallenge",
			opts: []RegistrationOption{withTestChallenge(bytes.Repeat([]byte{0xab}, 8))},
			err:  "error generating credential creation: the challenge must be at least 16 bytes",
		},
		{
			name: "ShouldFailFifteenByteChallenge",
			opts: []RegistrationOption{withTestChallenge(bytes.Repeat([]byte{0xab}, 15))},
			err:  "error generating credential creation: the challenge must be at least 16 bytes",
		},
		{
			name:   "ShouldSucceedSixteenByteChallenge",
			opts:   []RegistrationOption{withTestChallenge(bytes.Repeat([]byte{0xab}, 16))},
			expLen: 16,
		},
		{
			name:   "ShouldSucceedThirtyTwoByteChallenge",
			opts:   []RegistrationOption{withTestChallenge(bytes.Repeat([]byte{0xab}, 32))},
			expLen: 32,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(config)
			require.NoError(t, err)

			user := &defaultUser{id: []byte("123")}

			creation, session, err := w.BeginMediatedRegistration(user, protocol.MediationDefault, tc.opts...)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.Nil(t, creation)
				assert.Nil(t, session)

				return
			}

			require.NoError(t, err)
			require.NotNil(t, creation)
			require.NotNil(t, session)
			assert.Len(t, []byte(creation.Response.Challenge), tc.expLen)
			assert.NotEmpty(t, session.Challenge)
			assert.Equal(t, creation.Response.Challenge.String(), session.Challenge)
		})
	}
}

func TestBeginMediatedRegistration_EnforceTimeout(t *testing.T) {
	config := &Config{
		RPID:          "example.com",
		RPDisplayName: "Test Display Name",
		RPOrigins:     []string{"https://example.com"},
		Timeouts: TimeoutsConfig{
			Registration: TimeoutConfig{
				Enforce: true,
				Timeout: time.Second * 60,
			},
		},
	}

	w, err := New(config)
	require.NoError(t, err)

	user := &defaultUser{id: []byte("123")}

	_, session, err := w.BeginMediatedRegistration(user, protocol.MediationConditional)
	require.NoError(t, err)
	assert.False(t, session.Expires.IsZero())
	assert.Equal(t, protocol.MediationConditional, session.Mediation)
}

func TestRegistrationOptions(t *testing.T) {
	tv := true
	fv := false

	testCases := []struct {
		name     string
		opts     []RegistrationOption
		have     protocol.PublicKeyCredentialCreationOptions
		expected protocol.PublicKeyCredentialCreationOptions
	}{
		{
			name: "Empty",
			opts: nil,
		},
		{
			name: "CredentialParametersDefault",
			opts: []RegistrationOption{WithCredentialParameters(CredentialParametersDefault())},
			expected: protocol.PublicKeyCredentialCreationOptions{
				Parameters: CredentialParametersDefault(),
			},
		},
		{
			name: "CredentialParametersL3Extended",
			opts: []RegistrationOption{WithCredentialParameters(CredentialParametersExtendedL3())},
			expected: protocol.PublicKeyCredentialCreationOptions{
				Parameters: CredentialParametersExtendedL3(),
			},
		},
		{
			name: "CredentialParametersL3Recommended",
			opts: []RegistrationOption{WithCredentialParameters(CredentialParametersRecommendedL3())},
			expected: protocol.PublicKeyCredentialCreationOptions{
				Parameters: CredentialParametersRecommendedL3(),
			},
		},
		{
			name: "Exclusions",
			opts: []RegistrationOption{WithExclusions([]protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("123"), Transport: []protocol.AuthenticatorTransport{protocol.Hybrid}}})},
			expected: protocol.PublicKeyCredentialCreationOptions{
				CredentialExcludeList: []protocol.CredentialDescriptor{
					{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("123"), Transport: []protocol.AuthenticatorTransport{protocol.Hybrid}},
				},
			},
		},
		{
			name: "Selections",
			opts: []RegistrationOption{WithAuthenticatorSelection(protocol.AuthenticatorSelection{
				AuthenticatorAttachment: protocol.CrossPlatform,
				RequireResidentKey:      &tv,
				ResidentKey:             protocol.ResidentKeyRequirementRequired,
				UserVerification:        protocol.VerificationRequired,
			})},
			expected: protocol.PublicKeyCredentialCreationOptions{
				AuthenticatorSelection: protocol.AuthenticatorSelection{
					AuthenticatorAttachment: protocol.CrossPlatform,
					RequireResidentKey:      &tv,
					ResidentKey:             protocol.ResidentKeyRequirementRequired,
					UserVerification:        protocol.VerificationRequired,
				},
			},
		},
		{
			name: "ResidentKeyRequirementRequired",
			opts: []RegistrationOption{WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired)},
			expected: protocol.PublicKeyCredentialCreationOptions{
				AuthenticatorSelection: protocol.AuthenticatorSelection{
					RequireResidentKey: &tv,
					ResidentKey:        protocol.ResidentKeyRequirementRequired,
				},
			},
		},
		{
			name: "ResidentKeyRequirementPreferred",
			opts: []RegistrationOption{WithResidentKeyRequirement(protocol.ResidentKeyRequirementPreferred)},
			expected: protocol.PublicKeyCredentialCreationOptions{
				AuthenticatorSelection: protocol.AuthenticatorSelection{
					RequireResidentKey: &fv,
					ResidentKey:        protocol.ResidentKeyRequirementPreferred,
				},
			},
		},
		{
			name: "PublicKeyCredentialHints",
			opts: []RegistrationOption{WithPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{
				protocol.PublicKeyCredentialHintSecurityKey,
			})},
			expected: protocol.PublicKeyCredentialCreationOptions{
				Hints: []protocol.PublicKeyCredentialHints{
					protocol.PublicKeyCredentialHintSecurityKey,
				},
			},
		},
		{
			name: "ConveyancePreference",
			opts: []RegistrationOption{WithConveyancePreference(protocol.PreferEnterpriseAttestation)},
			expected: protocol.PublicKeyCredentialCreationOptions{
				Attestation: protocol.PreferEnterpriseAttestation,
			},
		},
		{
			name: "AttestationFormats",
			opts: []RegistrationOption{WithAttestationFormats([]protocol.AttestationFormat{protocol.AttestationFormatPacked})},
			expected: protocol.PublicKeyCredentialCreationOptions{
				AttestationFormats: []protocol.AttestationFormat{protocol.AttestationFormatPacked},
			},
		},
		{
			name: "Extensions",
			opts: []RegistrationOption{WithExtensions(map[string]any{"appID": "example"})},
			expected: protocol.PublicKeyCredentialCreationOptions{
				Extensions: map[string]any{"appID": "example"},
			},
		},
		{
			name:     "AppIDExcludeExtensionWithNoExclusions",
			opts:     []RegistrationOption{WithAppIdExcludeExtension("apple")},
			expected: protocol.PublicKeyCredentialCreationOptions{},
		},
		{
			name: "AppIDExcludeExtensionWithExclusions",
			opts: []RegistrationOption{WithExclusions([]protocol.CredentialDescriptor{
				{Type: protocol.PublicKeyCredentialType, AttestationType: protocol.CredentialTypeFIDOU2F, CredentialID: []byte("123"), Transport: []protocol.AuthenticatorTransport{protocol.Hybrid}},
			}), WithAppIdExcludeExtension("apple")},
			expected: protocol.PublicKeyCredentialCreationOptions{
				CredentialExcludeList: []protocol.CredentialDescriptor{
					{Type: protocol.PublicKeyCredentialType, AttestationType: protocol.CredentialTypeFIDOU2F, CredentialID: []byte("123"), Transport: []protocol.AuthenticatorTransport{protocol.Hybrid}},
				},
				Extensions: map[string]any{"appidExclude": "apple"},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			opts := &tc.have

			for _, opt := range tc.opts {
				opt(opts)
			}

			assert.Equal(t, tc.expected, *opts)
		})
	}
}

func TestCreateCredential_Full(t *testing.T) {
	credParams := []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}

	testCases := []struct {
		name string
		have struct {
			specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
			challenge  string
			mediation  protocol.CredentialMediationRequirement
			setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
		}
		expected struct {
			attestationType string
			err             string
		}
	}{
		{
			name: "ShouldSucceedNoneFormat",
			have: struct {
				specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
				challenge  string
				mediation  protocol.CredentialMediationRequirement
				setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
			}{
				specVector: testRegistrationSpecVectorNoneES256,
			},
			expected: struct {
				attestationType string
				err             string
			}{
				attestationType: "none",
			},
		},
		{
			name: "ShouldSucceedPackedSelfFormat",
			have: struct {
				specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
				challenge  string
				mediation  protocol.CredentialMediationRequirement
				setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
			}{
				specVector: testRegistrationSpecVectorPackedSelfES256,
			},
			expected: struct {
				attestationType string
				err             string
			}{
				attestationType: "packed",
			},
		},
		{
			name: "ShouldSucceedWithMDS",
			have: struct {
				specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
				challenge  string
				mediation  protocol.CredentialMediationRequirement
				setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
			}{
				specVector: testRegistrationSpecVectorPackedSelfES256,
				setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
					t.Helper()

					provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
					provider.EXPECT().GetValidateEntry(gomock.Any()).Return(false)
				},
			},
			expected: struct {
				attestationType string
				err             string
			}{
				attestationType: "packed",
			},
		},
		{
			name: "ShouldFailWithMDSGetEntryError",
			have: struct {
				specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
				challenge  string
				mediation  protocol.CredentialMediationRequirement
				setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
			}{
				specVector: testRegistrationSpecVectorPackedSelfES256,
				setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
					t.Helper()

					provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("entry lookup failed"))
				},
			},
			expected: struct {
				attestationType string
				err             string
			}{
				err: "Failed to validate authenticator metadata for Authenticator Attestation GUID 'df850e09-db6a-fbdf-ab51-697791506cfc'. Error occurred retrieving the metadata entry: entry lookup failed",
			},
		},
		{
			name: "ShouldSucceedWithMDSValidateStatusReports",
			have: struct {
				specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
				challenge  string
				mediation  protocol.CredentialMediationRequirement
				setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
			}{
				specVector: testRegistrationSpecVectorPackedSelfES256,
				setup: func(t *testing.T, provider *mocks.MockMetadataProvider) {
					t.Helper()

					provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(&metadata.Entry{
						MetadataStatement: metadata.Statement{
							AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicSurrogate},
						},
					}, nil)
					provider.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(true)
					provider.EXPECT().GetValidateStatus(gomock.Any()).Return(true)
					provider.EXPECT().ValidateStatusReports(gomock.Any(), gomock.Any()).Return(nil)
					provider.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(false)
				},
			},
			expected: struct {
				attestationType string
				err             string
			}{
				attestationType: "packed",
			},
		},
		{
			name: "ShouldFailVerifyError",
			have: struct {
				specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
				challenge  string
				mediation  protocol.CredentialMediationRequirement
				setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
			}{
				specVector: testRegistrationSpecVectorNoneES256,
				challenge:  "wrong-challenge",
			},
			expected: struct {
				attestationType string
				err             string
			}{
				err: "Error validating challenge",
			},
		},
		{
			name: "ShouldSucceedMediationConditional",
			have: struct {
				specVector func(t *testing.T) (body []byte, challenge string, credentialID []byte)
				challenge  string
				mediation  protocol.CredentialMediationRequirement
				setup      func(t *testing.T, provider *mocks.MockMetadataProvider)
			}{
				specVector: testRegistrationSpecVectorNoneES256,
				mediation:  protocol.MediationConditional,
			},
			expected: struct {
				attestationType string
				err             string
			}{
				attestationType: "none",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, challenge, credentialID := tc.have.specVector(t)

			parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
			require.NoError(t, err)

			if tc.have.challenge != "" {
				challenge = tc.have.challenge
			}

			userID := []byte("test-user-id")

			config := &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
			}

			if tc.have.setup != nil {
				ctrl := gomock.NewController(t)

				provider := mocks.NewMockMetadataProvider(ctrl)

				tc.have.setup(t, provider)

				config.MDS = provider
			}

			w := &WebAuthn{Config: config}

			session := SessionData{
				Challenge:  challenge,
				UserID:     userID,
				CredParams: credParams,
				Mediation:  tc.have.mediation,
			}

			user := &defaultUser{id: userID}

			credential, err := w.CreateCredential(user, session, parsedResponse)

			if tc.expected.err != "" {
				assert.Nil(t, credential)
				assert.EqualError(t, err, tc.expected.err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, credential)
				assert.Equal(t, credentialID, credential.ID)
				assert.Equal(t, tc.expected.attestationType, credential.AttestationType)
			}
		})
	}
}

func TestFinishRegistration_Success(t *testing.T) {
	body, challenge, credentialID := testRegistrationSpecVectorNoneES256(t)
	credParams := []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}}

	userID := []byte("test-user-id")

	w := &WebAuthn{
		Config: &Config{
			RPID:      "example.org",
			RPOrigins: []string{"https://example.org"},
		},
	}

	session := SessionData{
		Challenge:  challenge,
		UserID:     userID,
		CredParams: credParams,
	}

	user := &defaultUser{id: userID}

	reqBody := io.NopCloser(bytes.NewReader(body))
	httpReq := &http.Request{Body: reqBody}

	credential, err := w.FinishRegistration(user, session, httpReq)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, credentialID, credential.ID)
	assert.Equal(t, "none", credential.AttestationType)
}

// testRegistrationSpecVectorNoneES256 returns the spec test vector data for NoneES256 registration.
// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256
func testRegistrationSpecVectorNoneES256(t *testing.T) (body []byte, challenge string, credentialID []byte) {
	t.Helper()

	const (
		attestationObjectHex = "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d"
		credentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
		challengeHex         = "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130"
	)

	credentialID, err := hex.DecodeString(credentialIDHex)
	require.NoError(t, err)

	challenge = base64.RawURLEncoding.EncodeToString(testRegDecodeHex(t, challengeHex))

	id := base64.RawURLEncoding.EncodeToString(credentialID)
	attObj := base64.RawURLEncoding.EncodeToString(testRegDecodeHex(t, attestationObjectHex))
	cdj := base64.RawURLEncoding.EncodeToString(testRegDecodeHex(t, clientDataJSONHex))

	response := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": attObj,
			"clientDataJSON":    cdj,
		},
	}

	body, err = json.Marshal(response)
	require.NoError(t, err)

	return body, challenge, credentialID
}

// testRegistrationSpecVectorPackedSelfES256 returns the spec test vector data for Packed Self ES256 registration.
// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-packed-self-es256
func testRegistrationSpecVectorPackedSelfES256(t *testing.T) (body []byte, challenge string, credentialID []byte) {
	t.Helper()

	const (
		attestationObjectHex = "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d"
		credentialIDHex      = "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c" //nolint:gosec
		challengeHex         = "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5"
	)

	credentialID, err := hex.DecodeString(credentialIDHex)
	require.NoError(t, err)

	challenge = base64.RawURLEncoding.EncodeToString(testRegDecodeHex(t, challengeHex))

	id := base64.RawURLEncoding.EncodeToString(credentialID)
	attObj := base64.RawURLEncoding.EncodeToString(testRegDecodeHex(t, attestationObjectHex))
	cdj := base64.RawURLEncoding.EncodeToString(testRegDecodeHex(t, clientDataJSONHex))

	response := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": attObj,
			"clientDataJSON":    cdj,
		},
	}

	body, err = json.Marshal(response)
	require.NoError(t, err)

	return body, challenge, credentialID
}

func testRegDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	data, err := hex.DecodeString(s)
	require.NoError(t, err)

	return data
}
