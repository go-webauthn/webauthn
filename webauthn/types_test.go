package webauthn

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestConfigValidateErr(t *testing.T) {
	testCases := []struct {
		name  string
		have  *Config
		err   string
		check func(t *testing.T, have *Config)
	}{
		{
			"ShouldNotErrorOnStandardConfig",
			&Config{
				RPID:          "example.com",
				RPDisplayName: "example",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"",
			nil,
		},
		{
			"ShouldErrorOnAbsoluteRPID",
			&Config{
				RPID:          "https://example.com",
				RPDisplayName: "example",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"field 'RPID' is an absolute URI but it must not be an absolute URI",
			nil,
		},
		{
			"ShouldSkipValidation",
			&Config{
				validated: true,
			},
			"",
			nil,
		},
		{
			"ShouldErrorOnBadRPIcon",
			&Config{
				RPID:          "example.com",
				RPIcon:        "exa$##$#@$@#%^@#mple.com",
				RPDisplayName: "example",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"field 'RPIcon' is not a valid URI: parse \"exa$##$#@$@#%^@#mple.com\": invalid URL escape \"%^@\"",
			nil,
		},
		{
			"ShouldErrorOnBadRPIconAbsolute",
			&Config{
				RPID:          "example.com",
				RPIcon:        "example.com",
				RPDisplayName: "example",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"field 'RPIcon' is not an absolute URI but it must be an absolute URI",
			nil,
		},
		{
			"ShouldSetFallbackRPOriginAndNotErr",
			&Config{
				RPID:          "example.com",
				RPDisplayName: "example",
				RPOrigin:      "https://example.com",
				RPOrigins:     []string{},
			},
			"",
			func(t *testing.T, have *Config) {
				require.Len(t, have.RPOrigins, 1)
				assert.Equal(t, "https://example.com", have.RPOrigins[0])
			},
		},
		{
			"ShouldNotErrorOnConfigWithoutRPID",
			&Config{
				RPDisplayName: "example",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"",
			nil,
		},
		{
			"ShouldErrorOnNoDisplayName",
			&Config{
				RPID: "example.com",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"the field 'RPDisplayName' must be configured but it is empty",
			nil,
		},
		{
			"ShouldErrorOnNoOrigins",
			&Config{
				RPID:          "example.com",
				RPDisplayName: "example",
				RPOrigins:     []string{},
			},
			"must provide at least one value to the 'RPOrigins' field",
			nil,
		},
		{
			"ShouldErrorOnInvalidRPID",
			&Config{
				RPID:          "exa$##$#@$@#%^@#mple.com",
				RPDisplayName: "example",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"field 'RPID' is not a valid URI: parse \"exa$##$#@$@#%^@#mple.com\": invalid URL escape \"%^@\"",
			nil,
		},
		{
			"ShouldErrorOnDeprecatedAndNewRPOrigins",
			&Config{
				RPID:          "example.com",
				RPDisplayName: "example",
				RPOrigin:      "https://example.com",
				RPOrigins: []string{
					"https://example.com",
				},
			},
			"deprecated field 'RPOrigin' can't be defined at the same tme as the replacement field 'RPOrigins'",
			nil,
		},
		{
			"ShouldSetDefaultTimeoutValues",
			&Config{
				RPID:          "example.com",
				RPDisplayName: "example",
				RPOrigins: []string{
					"https://example.com",
				},
				Timeout: int(time.Second.Milliseconds()),
			},
			"",
			func(t *testing.T, have *Config) {
				assert.Equal(t, time.Second, have.Timeouts.Login.Timeout)
				assert.Equal(t, time.Second, have.Timeouts.Login.TimeoutUVD)
				assert.Equal(t, time.Second, have.Timeouts.Registration.Timeout)
				assert.Equal(t, time.Second, have.Timeouts.Registration.TimeoutUVD)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.have.validate()

			if len(tc.err) == 0 {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}

			if tc.check != nil {
				tc.check(t, tc.have)
			}
		})
	}
}
