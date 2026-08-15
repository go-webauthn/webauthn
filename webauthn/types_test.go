package webauthn

import (
	"testing"

	"github.com/google/uuid"
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
		expectedOpaqueOrigins         []string
		expectedTopOrigins            []string
		expectedTopOriginVerification protocol.TopOriginVerificationMode
		expectedMetaDataProviderIsNil bool
		expectedAttestationPolicy     protocol.AttestationPolicy
	}{
		{
			name: "ShouldReturnAllValues",
			config: &Config{
				RPID:                        "example.com",
				RPOrigins:                   []string{"https://example.com"},
				RPOpaqueOrigins:             []string{"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
				RPTopOrigins:                []string{"https://top.example.com"},
				RPTopOriginVerificationMode: protocol.TopOriginExplicitVerificationMode,
				Attestation: protocol.AttestationPolicy{
					AndroidKey: protocol.AndroidKeyPolicy{AuthorizationScope: protocol.AndroidKeyAuthorizationScopeUnion},
				},
			},
			expectedRPID:                  "example.com",
			expectedOrigins:               []string{"https://example.com"},
			expectedOpaqueOrigins:         []string{"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			expectedTopOrigins:            []string{"https://top.example.com"},
			expectedTopOriginVerification: protocol.TopOriginExplicitVerificationMode,
			expectedMetaDataProviderIsNil: true,
			expectedAttestationPolicy: protocol.AttestationPolicy{
				AndroidKey: protocol.AndroidKeyPolicy{AuthorizationScope: protocol.AndroidKeyAuthorizationScopeUnion},
			},
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
			expectedAttestationPolicy:     protocol.AttestationPolicy{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expectedRPID, tc.config.GetRPID())
			assert.Equal(t, tc.expectedOrigins, tc.config.GetOrigins())
			assert.Equal(t, tc.expectedOpaqueOrigins, tc.config.GetOpaqueOrigins())
			assert.Equal(t, tc.expectedTopOrigins, tc.config.GetTopOrigins())
			assert.Equal(t, tc.expectedTopOriginVerification, tc.config.GetTopOriginVerificationMode())
			assert.Equal(t, tc.expectedAttestationPolicy, tc.config.GetAttestationPolicy())

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

func TestConfig_Validate_OpaqueOrigins(t *testing.T) {
	testCases := []struct {
		name   string
		config *Config
		err    string
	}{
		{
			name: "ShouldPassOpaqueOriginsAlongsideNonOpaqueOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com", "https://example.com.au"},
				RPTopOrigins:    []string{"https://top.example.com"},
				RPOpaqueOrigins: []string{"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			},
		},
		{
			name: "ShouldPassAnOpaqueOriginInRPOriginsWhenNoOpaqueOriginsAreConfigured",
			config: &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com", "android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			},
		},
		{
			name: "ShouldPassMoreThanTheRelatedOriginLabelBudgetWhenNoOpaqueOriginsAreConfigured",
			config: &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com", "https://f.com"},
			},
		},
		{
			name: "ShouldFailAnOpaqueOriginInRPOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com", "android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
				RPOpaqueOrigins: []string{"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			},
			err: "error occurred validating the configuration: when the 'RPOpaqueOrigins' field is configured the 'RPOrigins' field must only contain origins a Related Origin Requests document can declare: error validating related origin 'android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk': the scheme must be either http or https but it is 'android'",
		},
		{
			name: "ShouldFailMoreThanTheRelatedOriginLabelBudgetInRPOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com", "https://f.com"},
				RPOpaqueOrigins: []string{"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			},
			err: "error occurred validating the configuration: when the 'RPOpaqueOrigins' field is configured the 'RPOrigins' field must only contain origins a Related Origin Requests document can declare: error validating related origins: the origins have 6 distinct registrable domain labels but clients only process 5 of them, so origins beyond that limit are ignored",
		},
		{
			name: "ShouldPassTheRelatedOriginLabelBudgetInRPOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://a.com", "https://b.com", "https://c.com", "https://d.com", "https://e.com", "https://www.a.com"},
				RPOpaqueOrigins: []string{"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			},
		},
		{
			name: "ShouldFailAnOpaqueOriginInRPTopOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com"},
				RPTopOrigins:    []string{"https://top.example.com", "android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
				RPOpaqueOrigins: []string{"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			},
			err: "error occurred validating the configuration: when the 'RPOpaqueOrigins' field is configured the 'RPTopOrigins' field must only contain origins a Related Origin Requests document can declare but the value 'android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk' is opaque",
		},
		{
			name: "ShouldFailANonOpaqueOriginInRPOpaqueOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com"},
				RPOpaqueOrigins: []string{"https://app.example.com"},
			},
			err: "error occurred validating the configuration: the 'RPOpaqueOrigins' field must only contain opaque origins but the value 'https://app.example.com' is not opaque; it belongs in the 'RPOrigins' field",
		},
		{
			name: "ShouldPassEveryKnownOpaqueOriginPrefixInRPOpaqueOrigins",
			config: &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
				RPOpaqueOrigins: []string{
					"android:apk-key-hash:2jmj7l5rSw0yVb-vlWAYkK-YBwk",
					"android:apk-key-hash-sha256:47DEQpj8HBSa-_TImW-5JCeuQeRkm5NMpJWZG3hSuFU",
					"android:apk-key-id:2jmj7l5rSw0yVb-vlWAYkK-YBwk",
					"ios:bundle-id:com.example.app",
					"ios:bundle-key:2jmj7l5rSw0yVb-vlWAYkK-YBwk",
					"chrome-extension://mbniclmhobmnbdlbpiphghaielnnpgdp",
					"moz-extension://d56a5b99-51b6-4e83-ab23-796216191c9d",
					"file://",
					"ms-appx://microsoft.windowscalculator_8wekyb3d8bbwe",
				},
			},
		},
		{
			name: "ShouldFailAnUnknownOpaqueOriginPrefixInRPOpaqueOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com"},
				RPOpaqueOrigins: []string{"safari-web-extension://d56a5b99-51b6-4e83-ab23-796216191c9d"},
			},
			err: "error occurred validating the configuration: " + errOpaqueOriginsUnknownPrefix + "'safari-web-extension://d56a5b99-51b6-4e83-ab23-796216191c9d' is not one of them",
		},
		{
			name: "ShouldFailAKnownOpaqueOriginPrefixWithoutAValueInRPOpaqueOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com"},
				RPOpaqueOrigins: []string{"android:apk-key-hash:"},
			},
			err: "error occurred validating the configuration: " + errOpaqueOriginsUnknownPrefix + "'android:apk-key-hash:' is not one of them",
		},
		{
			name: "ShouldFailAKnownOpaqueOriginPrefixInTheWrongCaseInRPOpaqueOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com"},
				RPOpaqueOrigins: []string{"ANDROID:APK-KEY-HASH:2jmj7l5rSw0yVb-vlWAYkK-YBwk"},
			},
			err: "error occurred validating the configuration: " + errOpaqueOriginsUnknownPrefix + "'ANDROID:APK-KEY-HASH:2jmj7l5rSw0yVb-vlWAYkK-YBwk' is not one of them",
		},
		{
			name: "ShouldFailAnOpaqueOriginResemblingAURLInRPOpaqueOrigins",
			config: &Config{
				RPID:            "example.com",
				RPOrigins:       []string{"https://example.com"},
				RPOpaqueOrigins: []string{"https://example.com:99999"},
			},
			err: "error occurred validating the configuration: " + errOpaqueOriginsUnknownPrefix + "'https://example.com:99999' is not one of them",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w, err := New(tc.config)

			if tc.err == "" {
				require.NoError(t, err)
				assert.NotNil(t, w)

				return
			}

			assert.Nil(t, w)
			assert.EqualError(t, err, tc.err)
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

func TestConfig_Validate_DefaultsAndroidKeyAuthorizationScopeToTEEEnforced(t *testing.T) {
	testCases := []struct {
		name     string
		scope    protocol.AndroidKeyAuthorizationScope
		expected protocol.AndroidKeyAuthorizationScope
	}{
		{
			name:     "ShouldCoerceDefaultToTEEEnforced",
			scope:    protocol.AndroidKeyAuthorizationScopeDefault,
			expected: protocol.AndroidKeyAuthorizationScopeTEEEnforced,
		},
		{
			name:     "ShouldPreserveExplicitTEEEnforced",
			scope:    protocol.AndroidKeyAuthorizationScopeTEEEnforced,
			expected: protocol.AndroidKeyAuthorizationScopeTEEEnforced,
		},
		{
			name:     "ShouldPreserveExplicitUnion",
			scope:    protocol.AndroidKeyAuthorizationScopeUnion,
			expected: protocol.AndroidKeyAuthorizationScopeUnion,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
				Attestation: protocol.AttestationPolicy{
					AndroidKey: protocol.AndroidKeyPolicy{AuthorizationScope: tc.scope},
				},
			}

			require.NoError(t, config.validate())
			assert.Equal(t, tc.expected, config.Attestation.AndroidKey.AuthorizationScope)
			assert.Equal(t, config.Attestation, config.GetAttestationPolicy())
		})
	}
}

func TestConfig_Validate_DefaultsCompoundSubStatementScopeToAll(t *testing.T) {
	testCases := []struct {
		name     string
		scope    protocol.CompoundSubStatementScope
		expected protocol.CompoundSubStatementScope
	}{
		{
			name:     "ShouldCoerceDefaultToAll",
			scope:    protocol.CompoundSubStatementScopeDefault,
			expected: protocol.CompoundSubStatementScopeAll,
		},
		{
			name:     "ShouldPreserveExplicitAll",
			scope:    protocol.CompoundSubStatementScopeAll,
			expected: protocol.CompoundSubStatementScopeAll,
		},
		{
			name:     "ShouldPreserveExplicitAny",
			scope:    protocol.CompoundSubStatementScopeAny,
			expected: protocol.CompoundSubStatementScopeAny,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
				Attestation: protocol.AttestationPolicy{
					Compound: protocol.CompoundPolicy{SubStatementScope: tc.scope},
				},
			}

			require.NoError(t, config.validate())
			assert.Equal(t, tc.expected, config.Attestation.Compound.SubStatementScope)
			assert.Equal(t, config.Attestation, config.GetAttestationPolicy())
		})
	}
}

func TestConfig_Validate_DefaultsECDSASignatureEncodingToDER(t *testing.T) {
	testCases := []struct {
		name     string
		encoding protocol.ECDSASignatureEncoding
		expected protocol.ECDSASignatureEncoding
	}{
		{
			name:     "ShouldCoerceDefaultToDER",
			encoding: protocol.ECDSASignatureEncodingDefault,
			expected: protocol.ECDSASignatureEncodingDER,
		},
		{
			name:     "ShouldPreserveExplicitDER",
			encoding: protocol.ECDSASignatureEncodingDER,
			expected: protocol.ECDSASignatureEncodingDER,
		},
		{
			name:     "ShouldPreserveExplicitBER",
			encoding: protocol.ECDSASignatureEncodingBER,
			expected: protocol.ECDSASignatureEncodingBER,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
				Signature: protocol.SignaturePolicy{ECDSAEncoding: tc.encoding},
			}

			require.NoError(t, config.validate())
			assert.Equal(t, tc.expected, config.Signature.ECDSAEncoding)
			assert.Equal(t, config.Signature, config.GetSignaturePolicy())
		})
	}
}

func TestConfig_Validate_FilteringMutuallyExclusive(t *testing.T) {
	aaguidA := uuid.MustParse("00000000-0000-0000-0000-00000000000a")
	aaguidB := uuid.MustParse("00000000-0000-0000-0000-00000000000b")

	testCases := []struct {
		name      string
		filtering *FilteringConfig
		err       string
	}{
		{
			name:      "ShouldAllowNilFiltering",
			filtering: nil,
		},
		{
			name:      "ShouldAllowEmptyFiltering",
			filtering: &FilteringConfig{},
		},
		{
			name:      "ShouldAllowPermittedOnly",
			filtering: &FilteringConfig{PermittedAAGUIDs: []uuid.UUID{aaguidA}},
		},
		{
			name:      "ShouldAllowProhibitedOnly",
			filtering: &FilteringConfig{ProhibitedAAGUIDs: []uuid.UUID{aaguidB}},
		},
		{
			name:      "ShouldAllowProhibitBackupEligibilityOnly",
			filtering: &FilteringConfig{ProhibitBackupEligibility: true},
		},
		{
			name: "ShouldAllowProhibitBackupEligibilityWithPermittedList",
			filtering: &FilteringConfig{
				ProhibitBackupEligibility: true,
				PermittedAAGUIDs:          []uuid.UUID{aaguidA},
			},
		},
		{
			name: "ShouldAllowProhibitBackupEligibilityWithProhibitedList",
			filtering: &FilteringConfig{
				ProhibitBackupEligibility: true,
				ProhibitedAAGUIDs:         []uuid.UUID{aaguidB},
			},
		},
		{
			name: "ShouldRejectBothPermittedAndProhibited",
			filtering: &FilteringConfig{
				PermittedAAGUIDs:  []uuid.UUID{aaguidA},
				ProhibitedAAGUIDs: []uuid.UUID{aaguidB},
			},
			err: "cannot set both 'PermittedAAGUIDs' and 'ProhibitedAAGUIDs' in the filtering config",
		},
		{
			name: "ShouldRejectBothPermittedAndProhibitedAlongsideBackupEligibility",
			filtering: &FilteringConfig{
				ProhibitBackupEligibility: true,
				PermittedAAGUIDs:          []uuid.UUID{aaguidA},
				ProhibitedAAGUIDs:         []uuid.UUID{aaguidB},
			},
			err: "cannot set both 'PermittedAAGUIDs' and 'ProhibitedAAGUIDs' in the filtering config",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			config := &Config{
				RPID:      "example.com",
				RPOrigins: []string{"https://example.com"},
				Filtering: tc.filtering,
			}

			err := config.validate()

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}

	t.Run("ShouldRejectViaNew", func(t *testing.T) {
		w, err := New(&Config{
			RPID:      "example.com",
			RPOrigins: []string{"https://example.com"},
			Filtering: &FilteringConfig{
				PermittedAAGUIDs:  []uuid.UUID{aaguidA},
				ProhibitedAAGUIDs: []uuid.UUID{aaguidB},
			},
		})

		assert.Nil(t, w)
		assert.EqualError(t, err, "error occurred validating the configuration: cannot set both 'PermittedAAGUIDs' and 'ProhibitedAAGUIDs' in the filtering config")
	})
}

const errOpaqueOriginsUnknownPrefix = "the 'RPOpaqueOrigins' field must only contain opaque origins a client conveys, i.e. one prefixed with 'android:apk-key-hash:', 'android:apk-key-hash-sha256:', 'android:apk-key-id:', 'ios:bundle-id:', 'ios:bundle-key:', 'chrome-extension://', 'moz-extension://', 'file://', or 'ms-appx://', but the value "

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
