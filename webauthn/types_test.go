package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestConfig_Getters(t *testing.T) {
	testCases := []struct {
		name                          string
		config                        *Config
		expectedRPID                  string
		expectedOrigins               []string
		expectedTopOrigins            []string
		expectedTopOriginVerification protocol.TopOriginVerificationMode
		expectedMetaDataProviderIsNil bool
	}{
		{
			name: "ShouldReturnAllValues",
			config: &Config{
				RPID:                        "example.com",
				RPOrigins:                   []string{"https://example.com"},
				RPTopOrigins:                []string{"https://top.example.com"},
				RPTopOriginVerificationMode: protocol.TopOriginExplicitVerificationMode,
			},
			expectedRPID:                  "example.com",
			expectedOrigins:               []string{"https://example.com"},
			expectedTopOrigins:            []string{"https://top.example.com"},
			expectedTopOriginVerification: protocol.TopOriginExplicitVerificationMode,
			expectedMetaDataProviderIsNil: true,
		},
		{
			name: "ShouldReturnDefaults",
			config: &Config{
				RPOrigins: []string{"https://example.com"},
			},
			expectedRPID:                  "",
			expectedOrigins:               []string{"https://example.com"},
			expectedTopOrigins:            nil,
			expectedTopOriginVerification: protocol.TopOriginDefaultVerificationMode,
			expectedMetaDataProviderIsNil: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedRPID, tc.config.GetRPID())
			assert.Equal(t, tc.expectedOrigins, tc.config.GetOrigins())
			assert.Equal(t, tc.expectedTopOrigins, tc.config.GetTopOrigins())
			assert.Equal(t, tc.expectedTopOriginVerification, tc.config.GetTopOriginVerificationMode())

			if tc.expectedMetaDataProviderIsNil {
				assert.Nil(t, tc.config.GetMetaDataProvider())
			} else {
				assert.NotNil(t, tc.config.GetMetaDataProvider())
			}
		})
	}
}

func TestNew(t *testing.T) {
	testCases := []struct {
		name   string
		config *Config
		err    string
	}{
		{
			name: "ShouldPassMinimalConfig",
			config: &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
			},
		},
		{
			name: "ShouldFailBadRPID",
			config: &Config{
				RPID:      "%%&&",
				RPOrigins: []string{"https://example.com"},
			},
			err: "error occurred validating the configuration: field 'RPID' is not a valid domain string: parse \"%%&&\": invalid URL escape \"%%&\"",
		},
		{
			name: "ShouldFailNoRPOrigins",
			config: &Config{
				RPID: "example.com",
			},
			err: "error occurred validating the configuration: must provide at least one value to the 'RPOrigins' field",
		},
		{
			name: "ShouldAllowEmptyRPTopOriginsExplicit",
			config: &Config{
				RPID:                        "example.com",
				RPOrigins:                   []string{"https://example.com"},
				RPTopOriginVerificationMode: protocol.TopOriginExplicitVerificationMode,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.config)

			if tc.err == "" {
				assert.NotNil(t, w)
				assert.NoError(t, err)
				assert.NoError(t, tc.config.validate())
			} else {
				assert.Nil(t, w)
				assert.EqualError(t, err, tc.err)
				assert.Error(t, tc.config.validate())
			}
		})
	}
}

func TestConfig_Validate_DefaultsRPTopOriginVerificationModeToExplicit(t *testing.T) {
	testCases := []struct {
		name   string
		input  protocol.TopOriginVerificationMode
		expect protocol.TopOriginVerificationMode
	}{
		{
			name:   "ShouldCoerceZeroValueToExplicit",
			input:  protocol.TopOriginVerificationMode(0),
			expect: protocol.TopOriginExplicitVerificationMode,
		},
		{
			name:   "ShouldCoerceDefaultToExplicit",
			input:  protocol.TopOriginDefaultVerificationMode,
			expect: protocol.TopOriginExplicitVerificationMode,
		},
		{
			name:   "ShouldPreserveExplicit",
			input:  protocol.TopOriginExplicitVerificationMode,
			expect: protocol.TopOriginExplicitVerificationMode,
		},
		{
			name:   "ShouldPreserveAuto",
			input:  protocol.TopOriginAutoVerificationMode,
			expect: protocol.TopOriginAutoVerificationMode,
		},
		{
			name:   "ShouldPreserveImplicit",
			input:  protocol.TopOriginImplicitVerificationMode,
			expect: protocol.TopOriginImplicitVerificationMode,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				RPID:                        "example.com",
				RPOrigins:                   []string{"https://example.com"},
				RPTopOriginVerificationMode: tc.input,
			}

			w, err := New(config)
			assert.NoError(t, err)
			assert.NotNil(t, w)
			assert.Equal(t, tc.expect, config.RPTopOriginVerificationMode,
				"Config.RPTopOriginVerificationMode should be %v after New(), got %v", tc.expect, config.RPTopOriginVerificationMode)
			assert.Equal(t, tc.expect, config.GetTopOriginVerificationMode())
		})
	}

	t.Run("ShouldCoerceDirectValidateCall", func(t *testing.T) {
		config := &Config{
			RPID:                        "example.com",
			RPOrigins:                   []string{"https://example.com"},
			RPTopOriginVerificationMode: protocol.TopOriginDefaultVerificationMode,
		}

		require.NoError(t, config.validate())
		assert.Equal(t, protocol.TopOriginExplicitVerificationMode, config.RPTopOriginVerificationMode)
	})
}

// Supporting test types and functions.

type defaultUser struct {
	id          []byte
	credentials []Credential
}

var _ User = (*defaultUser)(nil)

func (user *defaultUser) WebAuthnID() []byte {
	return user.id
}

func (user *defaultUser) WebAuthnName() string {
	return "newUser"
}

func (user *defaultUser) WebAuthnDisplayName() string {
	return "New User"
}

func (user *defaultUser) WebAuthnCredentials() []Credential {
	return user.credentials
}
