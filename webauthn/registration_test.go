package webauthn

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
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
