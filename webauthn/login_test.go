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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/testing/mocks"
)

func TestLogin_FinishLoginFailure(t *testing.T) {
	user := &defaultUser{
		id: []byte("123"),
	}

	session := SessionData{
		UserID: []byte("ABC"),
	}

	webauthn := &WebAuthn{}

	credential, err := webauthn.FinishLogin(user, session, nil)
	if err == nil {
		t.Errorf("FinishLogin() error = nil, want %v", protocol.ErrBadRequest.Type)
	}

	if credential != nil {
		t.Errorf("FinishLogin() credential = %v, want nil", credential)
	}
}

func TestWithLoginRelyingPartyID(t *testing.T) {
	testCases := []struct {
		name              string
		have              *Config
		opts              []LoginOption
		expectedID        string
		expectedChallenge []byte
		err               string
	}{
		{
			name: "OptionDefinedInConfig",
			have: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts:       nil,
			expectedID: "example.com",
		},
		{
			name: "OptionDefinedInConfigAndOpts",
			have: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts:       []LoginOption{WithLoginRelyingPartyID("a.example.com")},
			expectedID: "a.example.com",
		},
		{
			name: "OptionDefinedInConfigWithNoErrAndInOptsWithError",
			have: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts: []LoginOption{WithLoginRelyingPartyID("---::~!!~@#M!@OIK#N!@IOK@@@@@@@@@@")},
			err:  "error generating assertion: the relying party id failed to validate as it's not a valid domain string with error: parse \"---::~!!~@\": first path segment in URL cannot contain colon",
		},
		{
			name: "OptionDefinedInOpts",
			have: &Config{
				RPOrigins: []string{"https://example.com"},
			},
			opts:       []LoginOption{WithLoginRelyingPartyID("example.com")},
			expectedID: "example.com",
		},
		{
			name: "OptionIDNotDefined",
			have: &Config{
				RPOrigins: []string{"https://example.com"},
			},
			opts: nil,
			err:  "error generating assertion: the relying party id must be provided via the configuration or a functional option for a login",
		},
		{
			name: "TooShortWithChallengeOption",
			have: &Config{
				RPID:          "example.com",
				RPOrigins:     []string{"https://example.com"},
				RPDisplayName: "Test Display Name",
			},
			opts: []LoginOption{WithChallenge([]byte("1234567890"))},
			err:  "error generating assertion: the challenge must be at least 16 bytes",
		},
		{
			name: "WithChallengeOption",
			have: &Config{
				RPID:          "example.com",
				RPOrigins:     []string{"https://example.com"},
				RPDisplayName: "Test Display Name",
			},
			opts:              []LoginOption{WithChallenge([]byte("00000000000000000000000000000000"))},
			expectedID:        "example.com",
			expectedChallenge: []byte("00000000000000000000000000000000"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.have)
			assert.NoError(t, err)

			user := &defaultUser{
				credentials: []Credential{
					{},
				},
			}

			creation, _, err := w.BeginLogin(user, tc.opts...)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
				require.NotNil(t, creation)
				assert.Equal(t, tc.expectedID, creation.Response.RelyingPartyID)

				if len(tc.expectedChallenge) > 0 {
					assert.Equal(t, protocol.URLEncodedBase64(tc.expectedChallenge).String(), creation.Response.Challenge.String())
				}
			}
		})
	}
}

func TestFinishLoginFailure(t *testing.T) {
	const (
		credentialID = "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng" //nolint:gosec
		userHandle   = "0ToAAAAAAAAAAA"
	)

	var (
		byteUserHandle, _       = base64.RawURLEncoding.DecodeString(userHandle)
		byteID, _               = base64.RawURLEncoding.DecodeString(credentialID)
		byteCredentialPubKey, _ = base64.RawURLEncoding.DecodeString("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI")
		byteAAGUID, _           = base64.RawURLEncoding.DecodeString("rc4AAjW8xgpkiwsl8fBVAw")
	)

	credentials := []Credential{
		{
			ID:        byteID,
			PublicKey: byteCredentialPubKey,
			Authenticator: Authenticator{
				AAGUID: byteAAGUID,
			},
		},
	}

	user := &defaultUser{
		id:          byteUserHandle,
		credentials: credentials,
	}

	session := SessionData{
		UserID:               byteUserHandle,
		Challenge:            "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k",
		AllowedCredentialIDs: [][]byte{[]byte("test"), byteID},
	}

	webauthn := &WebAuthn{
		Config: &Config{
			RPDisplayName: "test_rp",
			RPOrigins:     []string{"https://webauthn.io"},
			RPID:          "webauthn.io",
		},
	}

	reqBody := io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf(`{
			"id":"%[1]s",
			"rawId":"%[1]s",
			"type":"public-key",
			"response":{
				"authenticatorData":"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
				"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
				"signature":"MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc",
				"userHandle":"%[2]s"
			}
		}`, credentialID, userHandle,
	))))
	httpReq := &http.Request{Body: reqBody}

	_, err := webauthn.FinishLogin(user, session, httpReq)

	require.Equal(t, protocol.ErrBadRequest.WithDetails("User does not own all credentials from the allowed credential list"), err)
}

func TestFinishLoginFailureCredentialOwnedButNotAllowedInSession(t *testing.T) {
	const (
		credentialIDOne = "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng" //nolint:gosec
		credentialIDTwo = "AI6D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng" //nolint:gosec
		userHandle      = "0ToAAAAAAAAAAA"
	)

	byteIDOne, err := base64.RawURLEncoding.DecodeString(credentialIDOne)
	require.NoError(t, err)

	byteIDTwo, err := base64.RawURLEncoding.DecodeString(credentialIDTwo)
	require.NoError(t, err)

	byteUserHandle, err := base64.RawURLEncoding.DecodeString(userHandle)
	require.NoError(t, err)

	byteCredentialPubKey, err := base64.RawURLEncoding.DecodeString("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI")
	require.NoError(t, err)

	byteAAGUID, err := base64.RawURLEncoding.DecodeString("rc4AAjW8xgpkiwsl8fBVAw")
	require.NoError(t, err)

	credentials := []Credential{
		{
			ID:        byteIDOne,
			PublicKey: byteCredentialPubKey,
			Authenticator: Authenticator{
				AAGUID: byteAAGUID,
			},
		},
		{
			ID:        byteIDTwo,
			PublicKey: byteCredentialPubKey,
			Authenticator: Authenticator{
				AAGUID: byteAAGUID,
			},
		},
	}

	user := &defaultUser{
		id:          byteUserHandle,
		credentials: credentials,
	}

	session := SessionData{
		UserID:               byteUserHandle,
		Challenge:            "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k",
		AllowedCredentialIDs: [][]byte{byteIDOne},
	}

	webauthn := &WebAuthn{
		Config: &Config{
			RPDisplayName: "test_rp",
			RPOrigins:     []string{"https://webauthn.io"},
			RPID:          "webauthn.io",
		},
	}

	reqBody := io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf(`{
			"id":"%[1]s",
			"rawId":"%[1]s",
			"type":"public-key",
			"response":{
				"authenticatorData":"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
				"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
				"signature":"MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc",
				"userHandle":"%[2]s"
			}
		}`, credentialIDTwo, userHandle,
	))))
	httpReq := &http.Request{Body: reqBody}

	_, err = webauthn.FinishLogin(user, session, httpReq)

	require.Equal(t, protocol.ErrBadRequest.WithDetails("The credential ID provided is not in the sessions allowed credential list"), err)
}

func TestFinishLoginFailureCredentialNotOwned(t *testing.T) {
	const (
		credentialIDOne = "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng" //nolint:gosec
		credentialIDTwo = "AI6D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng" //nolint:gosec
		userHandle      = "0ToAAAAAAAAAAA"
	)

	byteIDOne, err := base64.RawURLEncoding.DecodeString(credentialIDOne)
	require.NoError(t, err)

	byteUserHandle, err := base64.RawURLEncoding.DecodeString(userHandle)
	require.NoError(t, err)

	byteCredentialPubKey, err := base64.RawURLEncoding.DecodeString("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI")
	require.NoError(t, err)

	byteAAGUID, err := base64.RawURLEncoding.DecodeString("rc4AAjW8xgpkiwsl8fBVAw")
	require.NoError(t, err)

	credentials := []Credential{
		{
			ID:        byteIDOne,
			PublicKey: byteCredentialPubKey,
			Authenticator: Authenticator{
				AAGUID: byteAAGUID,
			},
		},
	}

	user := &defaultUser{
		id:          byteUserHandle,
		credentials: credentials,
	}

	session := SessionData{
		UserID:               byteUserHandle,
		Challenge:            "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k",
		AllowedCredentialIDs: [][]byte{byteIDOne},
	}

	webauthn := &WebAuthn{
		Config: &Config{
			RPDisplayName: "test_rp",
			RPOrigins:     []string{"https://webauthn.io"},
			RPID:          "webauthn.io",
		},
	}

	reqBody := io.NopCloser(bytes.NewReader([]byte(fmt.Sprintf(`{
			"id":"%[1]s",
			"rawId":"%[1]s",
			"type":"public-key",
			"response":{
				"authenticatorData":"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
				"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
				"signature":"MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc",
				"userHandle":"%[2]s"
			}
		}`, credentialIDTwo, userHandle,
	))))
	httpReq := &http.Request{Body: reqBody}

	_, err = webauthn.FinishLogin(user, session, httpReq)

	require.Equal(t, &protocol.ErrorUnknownCredential{Err: protocol.ErrBadRequest.WithDetails("The credential ID provided is not owned by the user")}, err)
}

func TestFinishDiscoverableLogin_Failure(t *testing.T) {
	session := SessionData{}
	webauthn := &WebAuthn{}

	credential, err := webauthn.FinishDiscoverableLogin(nil, session, nil)
	assert.Nil(t, credential)
	assert.Error(t, err)
}

func TestFinishPasskeyLogin_Failure(t *testing.T) {
	session := SessionData{}
	webauthn := &WebAuthn{}

	user, credential, err := webauthn.FinishPasskeyLogin(nil, session, nil)
	assert.Nil(t, user)
	assert.Nil(t, credential)
	assert.Error(t, err)
}

func TestBeginLogin_EnforceTimeout(t *testing.T) {
	config := &Config{
		RPID:          "example.com",
		RPDisplayName: "Test Display Name",
		RPOrigins:     []string{"https://example.com"},
		Timeouts: TimeoutsConfig{
			Login: TimeoutConfig{
				Enforce: true,
				Timeout: time.Second * 60,
			},
		},
	}

	w, err := New(config)
	require.NoError(t, err)

	user := &defaultUser{
		credentials: []Credential{{}},
	}

	_, session, err := w.BeginLogin(user)
	require.NoError(t, err)
	assert.False(t, session.Expires.IsZero())
}

func TestBeginDiscoverableLogin(t *testing.T) {
	testCases := []struct {
		name       string
		config     *Config
		opts       []LoginOption
		expectedID string
		err        string
	}{
		{
			name: "ShouldSucceed",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			expectedID: "example.com",
		},
		{
			name: "ShouldSucceedWithOpts",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts:       []LoginOption{WithUserVerification(protocol.VerificationRequired)},
			expectedID: "example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.config)
			require.NoError(t, err)

			assertion, session, err := w.BeginDiscoverableLogin(tc.opts...)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, assertion)
				require.NotNil(t, session)
				assert.Equal(t, tc.expectedID, assertion.Response.RelyingPartyID)
				assert.Empty(t, session.UserID)
				assert.Empty(t, session.AllowedCredentialIDs)
			}
		})
	}
}

func TestBeginDiscoverableMediatedLogin(t *testing.T) {
	testCases := []struct {
		name              string
		config            *Config
		mediation         protocol.CredentialMediationRequirement
		expectedID        string
		expectedMediation protocol.CredentialMediationRequirement
	}{
		{
			name: "ShouldSucceedConditional",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			mediation:         protocol.MediationConditional,
			expectedID:        "example.com",
			expectedMediation: protocol.MediationConditional,
		},
		{
			name: "ShouldSucceedRequired",
			config: &Config{
				RPID:          "example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			mediation:         protocol.MediationRequired,
			expectedID:        "example.com",
			expectedMediation: protocol.MediationRequired,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.config)
			require.NoError(t, err)

			assertion, session, err := w.BeginDiscoverableMediatedLogin(tc.mediation)
			require.NoError(t, err)
			require.NotNil(t, assertion)
			require.NotNil(t, session)
			assert.Equal(t, tc.expectedID, assertion.Response.RelyingPartyID)
			assert.Equal(t, tc.expectedMediation, assertion.Mediation)
			assert.Empty(t, session.UserID)
		})
	}
}

func TestBeginMediatedLogin_NoCredentials(t *testing.T) {
	config := &Config{
		RPID:          "example.com",
		RPDisplayName: "Test Display Name",
		RPOrigins:     []string{"https://example.com"},
	}

	w, err := New(config)
	require.NoError(t, err)

	user := &defaultUser{
		id:          []byte("123"),
		credentials: nil,
	}

	assertion, session, err := w.BeginMediatedLogin(user, protocol.MediationDefault)
	assert.Nil(t, assertion)
	assert.Nil(t, session)
	assert.EqualError(t, err, "Found no credentials for user")
}

func TestBeginLogin_Timeouts(t *testing.T) {
	testCases := []struct {
		name            string
		config          *Config
		opts            []LoginOption
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

			user := &defaultUser{
				credentials: []Credential{{}},
			}

			assertion, _, err := w.BeginLogin(user, tc.opts...)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedTimeout, assertion.Response.Timeout)
		})
	}
}

func TestValidateLogin_Errors(t *testing.T) {
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

			credential, err := w.ValidateLogin(tc.user, tc.session, nil)
			assert.Nil(t, credential)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestValidatePasskeyLogin_Errors(t *testing.T) {
	testCases := []struct {
		name    string
		handler DiscoverableUserHandler
		session SessionData
		parsed  *protocol.ParsedCredentialAssertionData
		err     string
	}{
		{
			name: "ShouldFailSessionNotDiscoverable",
			session: SessionData{
				UserID: []byte("123"),
			},
			err: "Session was not initiated as a client-side discoverable login",
		},
		{
			name: "ShouldFailSessionExpired",
			session: SessionData{
				Expires: time.Now().Add(-time.Hour),
			},
			err: "Session has Expired",
		},
		{
			name:    "ShouldFailBlankUserHandle",
			session: SessionData{},
			parsed: &protocol.ParsedCredentialAssertionData{
				ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
					RawID: []byte("cred-id"),
				},
				Response: protocol.ParsedAssertionResponse{},
			},
			err: "Client-side Discoverable Assertion was attempted with a blank User Handle",
		},
		{
			name: "ShouldFailHandlerError",
			handler: func(rawID, userHandle []byte) (User, error) {
				return nil, fmt.Errorf("user not found")
			},
			session: SessionData{},
			parsed: &protocol.ParsedCredentialAssertionData{
				ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
					RawID: []byte("cred-id"),
				},
				Response: protocol.ParsedAssertionResponse{
					UserHandle: []byte("user-handle"),
				},
			},
			err: "Failed to lookup Client-side Discoverable Credential: user not found",
		},
		{
			name: "ShouldFailHandlerReturnsNilUser",
			handler: func(rawID, userHandle []byte) (User, error) {
				return nil, nil
			},
			session: SessionData{},
			parsed: &protocol.ParsedCredentialAssertionData{
				ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
					RawID: []byte("cred-id"),
				},
				Response: protocol.ParsedAssertionResponse{
					UserHandle: []byte("user-handle"),
				},
			},
			err: "Failed to lookup Client-side Discoverable Credential: handler returned a nil user",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := &WebAuthn{Config: &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
			}}

			user, credential, err := w.ValidatePasskeyLogin(tc.handler, tc.session, tc.parsed)
			assert.Nil(t, user)
			assert.Nil(t, credential)
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestValidateDiscoverableLogin_Errors(t *testing.T) {
	w := &WebAuthn{Config: &Config{
		RPID:      "example.com",
		RPOrigins: []string{"https://example.com"},
	}}

	credential, err := w.ValidateDiscoverableLogin(nil, SessionData{UserID: []byte("123")}, nil)
	assert.Nil(t, credential)
	require.EqualError(t, err, "Session was not initiated as a client-side discoverable login")
}

func TestLoginOptions(t *testing.T) {
	testCases := []struct {
		name     string
		opts     []LoginOption
		have     protocol.PublicKeyCredentialRequestOptions
		expected protocol.PublicKeyCredentialRequestOptions
	}{
		{
			name: "Empty",
			opts: nil,
		},
		{
			name: "AllowedCredentials",
			opts: []LoginOption{WithAllowedCredentials([]protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("123")}})},
			expected: protocol.PublicKeyCredentialRequestOptions{
				AllowedCredentials: []protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("123")}},
			},
		},
		{
			name: "UserVerification",
			opts: []LoginOption{WithUserVerification(protocol.VerificationRequired)},
			expected: protocol.PublicKeyCredentialRequestOptions{
				UserVerification: protocol.VerificationRequired,
			},
		},
		{
			name: "PublicKeyCredentialHints",
			opts: []LoginOption{WithAssertionPublicKeyCredentialHints([]protocol.PublicKeyCredentialHints{protocol.PublicKeyCredentialHintSecurityKey})},
			expected: protocol.PublicKeyCredentialRequestOptions{
				Hints: []protocol.PublicKeyCredentialHints{protocol.PublicKeyCredentialHintSecurityKey},
			},
		},
		{
			name: "Extensions",
			opts: []LoginOption{WithAssertionExtensions(protocol.AuthenticationExtensions{"example": "extension"})},
			expected: protocol.PublicKeyCredentialRequestOptions{
				Extensions: protocol.AuthenticationExtensions{"example": "extension"},
			},
		},
		{
			name: "AppIDExtensionWithoutU2F",
			opts: []LoginOption{WithAllowedCredentials([]protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("123")}}), WithAppIdExtension("example")},
			expected: protocol.PublicKeyCredentialRequestOptions{
				AllowedCredentials: []protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, CredentialID: []byte("123")}},
			},
		},
		{
			name: "AppIDExtensionWithU2F",
			opts: []LoginOption{WithAllowedCredentials([]protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, AttestationType: protocol.CredentialTypeFIDOU2F, CredentialID: []byte("123")}}), WithAppIdExtension("example")},
			expected: protocol.PublicKeyCredentialRequestOptions{
				AllowedCredentials: []protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, AttestationType: protocol.CredentialTypeFIDOU2F, CredentialID: []byte("123")}},
				Extensions:         protocol.AuthenticationExtensions{protocol.ExtensionAppID: "example"},
			},
		},
		{
			name: "RelyingPartyID",
			opts: []LoginOption{WithLoginRelyingPartyID("example.com")},
			expected: protocol.PublicKeyCredentialRequestOptions{
				RelyingPartyID: "example.com",
			},
		},
		{
			name: "Challenge",
			opts: []LoginOption{WithChallenge([]byte("00000000000000000000000000000000"))},
			expected: protocol.PublicKeyCredentialRequestOptions{
				Challenge: []byte("00000000000000000000000000000000"),
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

func TestValidateLogin_Full(t *testing.T) {
	parsedResponse, credPubKey, challenge, credentialID := testLoginSpecVectorNoneES256(t)

	webauthn := &WebAuthn{
		Config: &Config{
			RPID:      "example.org",
			RPOrigins: []string{"https://example.org"},
		},
	}

	userID := []byte("test-user-id")

	t.Run("ShouldSucceedNoAllowedCredentials", func(t *testing.T) {
		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: credPubKey,
					Flags: CredentialFlags{
						UserPresent:    true,
						BackupEligible: true,
					},
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		credential, err := webauthn.ValidateLogin(user, session, parsedResponse)
		require.NoError(t, err)
		require.NotNil(t, credential)
		assert.Equal(t, credentialID, credential.ID)
		assert.True(t, credential.Flags.UserPresent)
	})

	t.Run("ShouldSucceedWithAllowedCredentials", func(t *testing.T) {
		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: credPubKey,
					Flags: CredentialFlags{
						UserPresent:    true,
						BackupEligible: true,
					},
				},
			},
		}

		session := SessionData{
			UserID:               userID,
			Challenge:            challenge,
			AllowedCredentialIDs: [][]byte{credentialID},
		}

		credential, err := webauthn.ValidateLogin(user, session, parsedResponse)
		require.NoError(t, err)
		require.NotNil(t, credential)
	})

	t.Run("ShouldFailUserHandleMismatch", func(t *testing.T) {
		parsedWithUserHandle, _, challengeUH, credIDUH := testLoginSpecVectorNoneES256(t)
		parsedWithUserHandle.Response.UserHandle = []byte("wrong-user-handle")

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credIDUH,
					PublicKey: credPubKey,
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challengeUH,
		}

		credential, err := webauthn.ValidateLogin(user, session, parsedWithUserHandle)
		assert.Nil(t, credential)
		assert.EqualError(t, err, "User handle and User ID do not match")
	})

	t.Run("ShouldFailCredentialNotFound", func(t *testing.T) {
		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        []byte("different-credential-id"),
					PublicKey: credPubKey,
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		credential, err := webauthn.ValidateLogin(user, session, parsedResponse)
		assert.Nil(t, credential)
		assert.EqualError(t, err, "Unable to find the credential for the returned credential ID")
	})

	t.Run("ShouldFailBackupEligibleFlagMismatch", func(t *testing.T) {
		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: credPubKey,
					Flags: CredentialFlags{
						UserPresent:    true,
						BackupEligible: false,
					},
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		credential, err := webauthn.ValidateLogin(user, session, parsedResponse)
		assert.Nil(t, credential)
		assert.EqualError(t, err, "Backup Eligible flag inconsistency detected during login validation")
	})

	t.Run("ShouldFailVerifyError", func(t *testing.T) {
		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: []byte("invalid-public-key"),
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		credential, err := webauthn.ValidateLogin(user, session, parsedResponse)
		assert.Nil(t, credential)
		require.Error(t, err)
	})

	t.Run("ShouldSucceedWithMDSNilAAGUID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		provider := mocks.NewMockMetadataProvider(ctrl)

		w := &WebAuthn{
			Config: &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
				MDS:       provider,
			},
		}

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: credPubKey,
					Flags: CredentialFlags{
						UserPresent:    true,
						BackupEligible: true,
					},
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
		provider.EXPECT().GetValidateEntryPermitZeroAAGUID(gomock.Any()).Return(true)

		credential, err := w.ValidateLogin(user, session, parsedResponse)
		require.NoError(t, err)
		require.NotNil(t, credential)
	})

	t.Run("ShouldFailWithMDSGetEntryError", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		provider := mocks.NewMockMetadataProvider(ctrl)

		w := &WebAuthn{
			Config: &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
				MDS:       provider,
			},
		}

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: credPubKey,
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, fmt.Errorf("entry not found"))

		credential, err := w.ValidateLogin(user, session, parsedResponse)
		assert.Nil(t, credential)
		assert.EqualError(t, err, "Failed to validate credential record metadata")
	})

	t.Run("ShouldSucceedWithMDSAndAAGUID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		provider := mocks.NewMockMetadataProvider(ctrl)

		w := &WebAuthn{
			Config: &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
				MDS:       provider,
			},
		}

		aaguid := []byte{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10}

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:              credentialID,
					PublicKey:       credPubKey,
					AttestationType: "packed",
					Flags: CredentialFlags{
						UserPresent:    true,
						BackupEligible: true,
					},
					Authenticator: Authenticator{
						AAGUID: aaguid,
					},
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
		provider.EXPECT().GetValidateEntry(gomock.Any()).Return(false)

		credential, err := w.ValidateLogin(user, session, parsedResponse)
		require.NoError(t, err)
		require.NotNil(t, credential)
	})

	t.Run("ShouldFailWithMDSInvalidAAGUID", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		provider := mocks.NewMockMetadataProvider(ctrl)

		w := &WebAuthn{
			Config: &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
				MDS:       provider,
			},
		}

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: credPubKey,
					Authenticator: Authenticator{
						AAGUID: []byte{0x01, 0x02, 0x03},
					},
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		credential, err := w.ValidateLogin(user, session, parsedResponse)
		assert.Nil(t, credential)
		assert.EqualError(t, err, "Failed to decode AAGUID")
	})

	t.Run("ShouldSucceedWithMDSValidateStatusReports", func(t *testing.T) {
		ctrl := gomock.NewController(t)

		provider := mocks.NewMockMetadataProvider(ctrl)

		w := &WebAuthn{
			Config: &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
				MDS:       provider,
			},
		}

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:              credentialID,
					PublicKey:       credPubKey,
					AttestationType: "packed",
					Flags: CredentialFlags{
						UserPresent:    true,
						BackupEligible: true,
					},
				},
			},
		}

		session := SessionData{
			UserID:    userID,
			Challenge: challenge,
		}

		provider.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(&metadata.Entry{
			MetadataStatement: metadata.Statement{
				AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
			},
		}, nil)
		provider.EXPECT().GetValidateStatus(gomock.Any()).Return(true)
		provider.EXPECT().ValidateStatusReports(gomock.Any(), gomock.Any()).Return(nil)
		provider.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(false)

		credential, err := w.ValidateLogin(user, session, parsedResponse)
		require.NoError(t, err)
		require.NotNil(t, credential)
	})
}

func TestValidatePasskeyLogin_Full(t *testing.T) {
	parsedResponse, credPubKey, challenge, credentialID := testLoginSpecVectorNoneES256(t)

	userID := []byte("test-user-id")
	parsedResponse.Response.UserHandle = userID

	t.Run("ShouldSucceed", func(t *testing.T) {
		w := &WebAuthn{
			Config: &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
			},
		}

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        credentialID,
					PublicKey: credPubKey,
					Flags: CredentialFlags{
						UserPresent:    true,
						BackupEligible: true,
					},
				},
			},
		}

		session := SessionData{
			Challenge: challenge,
		}

		handler := func(rawID, userHandle []byte) (User, error) {
			return user, nil
		}

		returnedUser, credential, err := w.ValidatePasskeyLogin(handler, session, parsedResponse)
		require.NoError(t, err)
		require.NotNil(t, returnedUser)
		require.NotNil(t, credential)
		assert.Equal(t, credentialID, credential.ID)
	})

	t.Run("ShouldFailValidateLoginError", func(t *testing.T) {
		w := &WebAuthn{
			Config: &Config{
				RPID:      "example.org",
				RPOrigins: []string{"https://example.org"},
			},
		}

		user := &defaultUser{
			id: userID,
			credentials: []Credential{
				{
					ID:        []byte("different-id"),
					PublicKey: credPubKey,
				},
			},
		}

		session := SessionData{
			Challenge: challenge,
		}

		handler := func(rawID, userHandle []byte) (User, error) {
			return user, nil
		}

		returnedUser, credential, err := w.ValidatePasskeyLogin(handler, session, parsedResponse)
		assert.Nil(t, returnedUser)
		assert.Nil(t, credential)
		require.Error(t, err)
	})
}

func TestFinishDiscoverableLogin_Success(t *testing.T) {
	parsedResponse, credPubKey, challenge, credentialID := testLoginSpecVectorNoneES256(t)

	userID := []byte("test-user-id")

	body := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(parsedResponse.Raw.AssertionResponse.AuthenticatorData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(parsedResponse.Raw.AssertionResponse.ClientDataJSON),
			"signature":         base64.RawURLEncoding.EncodeToString(parsedResponse.Response.Signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userID),
		},
	}

	data, err := json.Marshal(body)
	require.NoError(t, err)

	w := &WebAuthn{
		Config: &Config{
			RPID:      "example.org",
			RPOrigins: []string{"https://example.org"},
		},
	}

	user := &defaultUser{
		id: userID,
		credentials: []Credential{
			{
				ID:        credentialID,
				PublicKey: credPubKey,
				Flags: CredentialFlags{
					UserPresent:    true,
					BackupEligible: true,
				},
			},
		},
	}

	session := SessionData{
		Challenge: challenge,
	}

	handler := func(rawID, userHandle []byte) (User, error) {
		return user, nil
	}

	reqBody := io.NopCloser(bytes.NewReader(data))
	httpReq := &http.Request{Body: reqBody}

	credential, err := w.FinishDiscoverableLogin(handler, session, httpReq)
	require.NoError(t, err)
	require.NotNil(t, credential)
	assert.Equal(t, credentialID, credential.ID)
}

func TestFinishPasskeyLogin_Success(t *testing.T) {
	parsedResponse, credPubKey, challenge, credentialID := testLoginSpecVectorNoneES256(t)

	userID := []byte("test-user-id")

	body := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID),
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(parsedResponse.Raw.AssertionResponse.AuthenticatorData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(parsedResponse.Raw.AssertionResponse.ClientDataJSON),
			"signature":         base64.RawURLEncoding.EncodeToString(parsedResponse.Response.Signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString(userID),
		},
	}

	data, err := json.Marshal(body)
	require.NoError(t, err)

	w := &WebAuthn{
		Config: &Config{
			RPID:      "example.org",
			RPOrigins: []string{"https://example.org"},
		},
	}

	user := &defaultUser{
		id: userID,
		credentials: []Credential{
			{
				ID:        credentialID,
				PublicKey: credPubKey,
				Flags: CredentialFlags{
					UserPresent:    true,
					BackupEligible: true,
				},
			},
		},
	}

	session := SessionData{
		Challenge: challenge,
	}

	handler := func(rawID, userHandle []byte) (User, error) {
		return user, nil
	}

	reqBody := io.NopCloser(bytes.NewReader(data))
	httpReq := &http.Request{Body: reqBody}

	returnedUser, credential, err := w.FinishPasskeyLogin(handler, session, httpReq)
	require.NoError(t, err)
	require.NotNil(t, returnedUser)
	require.NotNil(t, credential)
	assert.Equal(t, credentialID, credential.ID)
}

// testLoginSpecVectorNoneES256 returns the spec test vector data for NoneES256 authentication.
// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256
func testLoginSpecVectorNoneES256(t *testing.T) (parsedResponse *protocol.ParsedCredentialAssertionData, credPubKey []byte, challenge string, credentialID []byte) {
	t.Helper()

	const (
		authenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
		signatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
		credentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
		challengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
		credentialPubKeyHex  = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	)

	credentialID, err := hex.DecodeString(credentialIDHex)
	require.NoError(t, err)

	credPubKey, err = hex.DecodeString(credentialPubKeyHex)
	require.NoError(t, err)

	challenge = base64.RawURLEncoding.EncodeToString(testDecodeHex(t, challengeHex))

	id := base64.RawURLEncoding.EncodeToString(credentialID)
	authenticatorData := base64.RawURLEncoding.EncodeToString(testDecodeHex(t, authenticatorDataHex))
	clientDataJSON := base64.RawURLEncoding.EncodeToString(testDecodeHex(t, clientDataJSONHex))
	signature := base64.RawURLEncoding.EncodeToString(testDecodeHex(t, signatureHex))

	body := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": authenticatorData,
			"clientDataJSON":    clientDataJSON,
			"signature":         signature,
		},
	}

	data, err := json.Marshal(body)
	require.NoError(t, err)

	parsedResponse, err = protocol.ParseCredentialRequestResponseBytes(data)
	require.NoError(t, err)

	return parsedResponse, credPubKey, challenge, credentialID
}

func testDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	data, err := hex.DecodeString(s)
	require.NoError(t, err)

	return data
}
