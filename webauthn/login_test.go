package webauthn

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
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
			opts: []LoginOption{WithAllowedCredentials([]protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, AttestationType: "basic_full", AttestationFormat: protocol.CredentialTypeFIDOU2F, CredentialID: []byte("123")}}), WithAppIdExtension("example")},
			expected: protocol.PublicKeyCredentialRequestOptions{
				AllowedCredentials: []protocol.CredentialDescriptor{{Type: protocol.PublicKeyCredentialType, AttestationType: "basic_full", AttestationFormat: protocol.CredentialTypeFIDOU2F, CredentialID: []byte("123")}},
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
