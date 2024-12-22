package webauthn

import (
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
				RPID:          "https://example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts:       nil,
			expectedID: "https://example.com",
		},
		{
			name: "OptionDefinedInConfigAndOpts",
			have: &Config{
				RPID:          "https://example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts:       []LoginOption{WithLoginRelyingPartyID("https://a.example.com")},
			expectedID: "https://a.example.com",
		},
		{
			name: "OptionDefinedInConfigWithNoErrAndInOptsWithError",
			have: &Config{
				RPID:          "https://example.com",
				RPDisplayName: "Test Display Name",
				RPOrigins:     []string{"https://example.com"},
			},
			opts: []LoginOption{WithLoginRelyingPartyID("---::~!!~@#M!@OIK#N!@IOK@@@@@@@@@@")},
			err:  "error generating assertion: the relying party id failed to validate as it's not a valid uri with error: parse \"---::~!!~@\": first path segment in URL cannot contain colon",
		},
		{
			name: "OptionDefinedInOpts",
			have: &Config{
				RPOrigins: []string{"https://example.com"},
			},
			opts:       []LoginOption{WithLoginRelyingPartyID("https://example.com")},
			expectedID: "https://example.com",
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
				RPID:          "https://example.com",
				RPOrigins:     []string{"https://example.com"},
				RPDisplayName: "Test Display Name",
			},
			opts: []LoginOption{WithChallenge([]byte("1234567890"))},
			err:  "error generating assertion: the challenge must be at least 16 bytes",
		},
		{
			name: "WithChallengeOption",
			have: &Config{
				RPID:          "https://example.com",
				RPOrigins:     []string{"https://example.com"},
				RPDisplayName: "Test Display Name",
			},
			opts:              []LoginOption{WithChallenge([]byte("00000000000000000000000000000000"))},
			expectedID:        "https://example.com",
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
