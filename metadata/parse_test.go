package metadata

import (
	"testing"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPayloadJSON_Parse(t *testing.T) {
	testCases := []struct {
		name string
		have PayloadJSON
		err  string
	}{
		{
			name: "ShouldFailInvalidNextUpdate",
			have: PayloadJSON{
				NextUpdate: "not-a-date",
			},
			err: "error occurred parsing next update value 'not-a-date': parsing time \"not-a-date\" as \"2006-01-02\": cannot parse \"not-a-date\" as \"2006\"",
		},
		{
			name: "ShouldFailInvalidEntry",
			have: PayloadJSON{
				NextUpdate: "2025-01-01",
				Entries: []EntryJSON{
					{
						TimeOfLastStatusChange: "not-a-date",
					},
				},
			},
			err: "error occurred parsing entry 0: error occurred parsing metadata entry with AAGUID '': error occurred parsing time of last status change value: parsing time \"not-a-date\" as \"2006-01-02\": cannot parse \"not-a-date\" as \"2006\"",
		},
		{
			name: "ShouldSucceedEmptyEntries",
			have: PayloadJSON{
				NextUpdate: "2025-01-01",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.have.Parse()

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestEntryJSON_Parse(t *testing.T) {
	testCases := []struct {
		name string
		have EntryJSON
		err  string
	}{
		{
			name: "ShouldFailInvalidAAGUID",
			have: EntryJSON{
				AaGUID:                 "not-a-uuid",
				TimeOfLastStatusChange: "2025-01-01",
			},
			err: "error occurred parsing metadata entry with AAGUID 'not-a-uuid': error parsing AAGUID: invalid UUID length: 10",
		},
		{
			name: "ShouldFailInvalidTimeOfLastStatusChange",
			have: EntryJSON{
				TimeOfLastStatusChange: "not-a-date",
			},
			err: "error occurred parsing metadata entry with AAGUID '': error occurred parsing time of last status change value: parsing time \"not-a-date\" as \"2006-01-02\": cannot parse \"not-a-date\" as \"2006\"",
		},
		{
			name: "ShouldFailInvalidBiometricStatusReport",
			have: EntryJSON{
				TimeOfLastStatusChange: "2025-01-01",
				BiometricStatusReports: []BiometricStatusReportJSON{
					{
						EffectiveDate: "bad",
					},
				},
			},
			err: "error occurred parsing metadata entry with AAGUID '': error occurred parsing biometric status report 0: error occurred parsing effective date value: parsing time \"bad\" as \"2006-01-02\": cannot parse \"bad\" as \"2006\"",
		},
		{
			name: "ShouldFailInvalidStatusReport",
			have: EntryJSON{
				TimeOfLastStatusChange: "2025-01-01",
				StatusReports: []StatusReportJSON{
					{
						EffectiveDate: "bad",
					},
				},
			},
			err: "error occurred parsing metadata entry with AAGUID '': error occurred parsing status report 0: error occurred parsing effective date value: parsing time \"bad\" as \"2006-01-02\": cannot parse \"bad\" as \"2006\"",
		},
		{
			name: "ShouldFailInvalidRogueListURL",
			have: EntryJSON{
				TimeOfLastStatusChange: "2025-01-01",
				StatusReports: []StatusReportJSON{
					{
						EffectiveDate: "2025-01-01",
					},
				},
				RogueListURL: "://bad-url",
			},
			err: "error occurred parsing metadata entry with AAGUID '': error occurred parsing rogue list URL value: parse \"://bad-url\": missing protocol scheme",
		},
		{
			name: "ShouldFailRogueListURLWithoutHash",
			have: EntryJSON{
				TimeOfLastStatusChange: "2025-01-01",
				StatusReports: []StatusReportJSON{
					{
						EffectiveDate: "2025-01-01",
					},
				},
				RogueListURL: "https://example.com/rogues",
			},
			err: "error occurred parsing metadata entry with AAGUID '': error occurred validating rogue list URL value: the rogue list hash was absent",
		},
		{
			name: "ShouldSucceedMinimal",
			have: EntryJSON{
				TimeOfLastStatusChange: "2025-01-01",
			},
		},
		{
			name: "ShouldSucceedWithStatusReportsWithoutEffectiveDate",
			have: EntryJSON{
				AaGUID:                 "0132d110-bf4e-4208-a403-ab4f5f12efe5",
				TimeOfLastStatusChange: "2025-01-01",
				StatusReports: []StatusReportJSON{
					{Status: FidoCertifiedL1},
				},
				BiometricStatusReports: []BiometricStatusReportJSON{
					{CertLevel: 1, Modality: "fingerprint"},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entry, err := tc.have.Parse()

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				return
			}

			assert.NoError(t, err)

			for i := range entry.StatusReports {
				if len(tc.have.StatusReports[i].EffectiveDate) == 0 {
					assert.Nil(t, entry.StatusReports[i].EffectiveDate, "status report %d", i)
				}
			}

			for i := range entry.BiometricStatusReports {
				if len(tc.have.BiometricStatusReports[i].EffectiveDate) == 0 {
					assert.Nil(t, entry.BiometricStatusReports[i].EffectiveDate, "biometric status report %d", i)
				}
			}
		})
	}
}

func TestStatementJSON_Parse(t *testing.T) {
	testCases := []struct {
		name string
		have StatementJSON
		err  string
	}{
		{
			name: "ShouldFailInvalidAAGUID",
			have: StatementJSON{
				AaGUID:      "not-a-uuid",
				Description: "test",
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing AAGUID value: invalid UUID length: 10",
		},
		{
			name: "ShouldFailInvalidAttestationRootCertificate",
			have: StatementJSON{
				Description:                 "test",
				AttestationRootCertificates: []string{"not-base64-cert"},
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing attestation root certificate 0 value: error occurred parsing *x509.certificate: error occurred decoding base64 data: illegal base64 data at input byte 3",
		},
		{
			name: "ShouldFailInvalidIcon",
			have: StatementJSON{
				Description: "test",
				Icon:        "://bad",
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing icon value: parse \"://bad\": missing protocol scheme",
		},
		{
			name: "ShouldFailInvalidIconDark",
			have: StatementJSON{
				Description: "test",
				IconDark:    "://bad",
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing icon dark value: parse \"://bad\": missing protocol scheme",
		},
		{
			name: "ShouldFailInvalidProviderLogoLight",
			have: StatementJSON{
				Description:       "test",
				ProviderLogoLight: "://bad",
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing provider logo light value: parse \"://bad\": missing protocol scheme",
		},
		{
			name: "ShouldFailInvalidProviderLogoDark",
			have: StatementJSON{
				Description:      "test",
				ProviderLogoDark: "://bad",
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing provider logo dark value: parse \"://bad\": missing protocol scheme",
		},
		{
			name: "ShouldFailInvalidCxConfigURL",
			have: StatementJSON{
				Description:                 "test",
				CredentialExchangeConfigURL: "://bad",
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing cx config url value: parse \"://bad\": missing protocol scheme",
		},
		{
			name: "ShouldFailInvalidAuthenticatorGetInfo",
			have: StatementJSON{
				Description: "test",
				AuthenticatorGetInfo: AuthenticatorGetInfoJSON{
					AaGUID: "not-a-uuid",
				},
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing authenticator get info value: error occurred parsing AAGUID value: invalid UUID length: 10",
		},
		{
			name: "ShouldSucceedMinimal",
			have: StatementJSON{
				Description: "test",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.have.Parse()

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestBiometricStatusReportJSON_Parse(t *testing.T) {
	testCases := []struct {
		name     string
		have     BiometricStatusReportJSON
		expected *time.Time
		err      string
	}{
		{
			name: "ShouldFailInvalidEffectiveDate",
			have: BiometricStatusReportJSON{
				EffectiveDate: "not-a-date",
			},
			err: "error occurred parsing effective date value: parsing time \"not-a-date\" as \"2006-01-02\": cannot parse \"not-a-date\" as \"2006\"",
		},
		{
			name: "ShouldSucceed",
			have: BiometricStatusReportJSON{
				EffectiveDate: "2025-01-01",
				CertLevel:     1,
			},
			expected: timePtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
		},
		{
			name: "ShouldSucceedWithoutEffectiveDate",
			have: BiometricStatusReportJSON{
				CertLevel: 1,
				Modality:  "fingerprint",
			},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := tc.have.Parse()

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				return
			}

			assert.NoError(t, err)
			assert.Equal(t, tc.expected, report.EffectiveDate)
		})
	}
}

func TestStatusReportJSON_Parse(t *testing.T) {
	testCases := []struct {
		name        string
		have        StatusReportJSON
		expected    StatusReport
		expectedURL string
		err         string
	}{
		{
			name: "ShouldFailInvalidEffectiveDate",
			have: StatusReportJSON{
				EffectiveDate: "not-a-date",
			},
			err: "error occurred parsing effective date value: parsing time \"not-a-date\" as \"2006-01-02\": cannot parse \"not-a-date\" as \"2006\"",
		},
		{
			name: "ShouldFailInvalidCertificate",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				Certificate:   "not-base64",
			},
			err: "error occurred parsing certificate value: error occurred parsing *x509.certificate: error occurred decoding base64 data: illegal base64 data at input byte 3",
		},
		{
			name: "ShouldFailInvalidBatchCertificate",
			have: StatusReportJSON{
				EffectiveDate:    "2025-01-01",
				BatchCertificate: "not-base64",
			},
			err: "error occurred parsing batch certificate value: error occurred parsing *x509.certificate: error occurred decoding base64 data: illegal base64 data at input byte 3",
		},
		{
			name: "ShouldFailInvalidSunsetDate",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				SunsetDate:    "bad",
			},
			err: "error occurred parsing sunset date value: parsing time \"bad\" as \"2006-01-02\": cannot parse \"bad\" as \"2006\"",
		},
		{
			name: "ShouldFailInvalidURL",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				URL:           string([]byte{0x7f}),
			},
			err: "error occurred parsing URL value: parse \"\\x7f\": net/url: invalid control character in URL",
		},
		{
			name: "ShouldFailInvalidURLWithScheme",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				URL:           "https://" + string([]byte{0x7f}),
			},
			err: "error occurred parsing URL value: parse \"https://\\x7f\": net/url: invalid control character in URL",
		},
		{
			name: "ShouldSucceedHostPrefixedWithHTTP",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				URL:           "httpbin.example.com/update",
			},
			expected: StatusReport{
				EffectiveDate: timePtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			expectedURL: "https://httpbin.example.com/update",
		},
		{
			name: "ShouldSucceedMinimal",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
			},
			expected: StatusReport{
				Status:        "",
				EffectiveDate: timePtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
		{
			name: "ShouldSucceedWithoutEffectiveDate",
			have: StatusReportJSON{
				Status: FidoCertifiedL1,
			},
			expected: StatusReport{
				Status:        FidoCertifiedL1,
				EffectiveDate: nil,
			},
		},
		{
			name: "ShouldSucceedWithSunsetDate",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				SunsetDate:    "2026-06-01",
			},
			expected: StatusReport{
				EffectiveDate: timePtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
				SunsetDate:    timePtr(time.Date(2026, 6, 1, 0, 0, 0, 0, time.UTC)),
			},
		},
		{
			name: "ShouldPreserveAllFields",
			have: StatusReportJSON{
				Status:                           FidoCertifiedL1,
				EffectiveDate:                    "2025-03-15",
				AuthenticatorVersion:             42,
				URL:                              "https://example.com/update",
				CertificationDescriptor:          "SecurityKey based on CC EAL 5 certified chip",
				CertificateNumber:                "FIDO2-CERT-001",
				CertificationPolicyVersion:       "1.4.0",
				CertificationProfiles:            []string{"consumer", "enterprise"},
				CertificationRequirementsVersion: "1.2.0",
				SunsetDate:                       "2030-12-31",
				FIPSRevision:                     3,
				FIPSPhysicalSecurityLevel:        2,
			},
			expected: StatusReport{
				Status:                           FidoCertifiedL1,
				EffectiveDate:                    timePtr(time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC)),
				AuthenticatorVersion:             42,
				CertificationDescriptor:          "SecurityKey based on CC EAL 5 certified chip",
				CertificateNumber:                "FIDO2-CERT-001",
				CertificationPolicyVersion:       "1.4.0",
				CertificationProfiles:            []string{"consumer", "enterprise"},
				CertificationRequirementsVersion: "1.2.0",
				SunsetDate:                       timePtr(time.Date(2030, 12, 31, 0, 0, 0, 0, time.UTC)),
				FIPSRevision:                     3,
				FIPSPhysicalSecurityLevel:        2,
			},
			expectedURL: "https://example.com/update",
		},
		{
			name: "ShouldSucceedURLWithoutScheme",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				URL:           "example.com/update",
			},
			expected: StatusReport{
				EffectiveDate: timePtr(time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC)),
			},
			expectedURL: "https://example.com/update",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.have.Parse()

			if tc.err == "" {
				assert.NoError(t, err)
				assert.Equal(t, tc.expected.Status, result.Status)
				assert.Equal(t, tc.expected.EffectiveDate, result.EffectiveDate)
				assert.Equal(t, tc.expected.AuthenticatorVersion, result.AuthenticatorVersion)
				assert.Equal(t, tc.expected.CertificationDescriptor, result.CertificationDescriptor)
				assert.Equal(t, tc.expected.CertificateNumber, result.CertificateNumber)
				assert.Equal(t, tc.expected.CertificationPolicyVersion, result.CertificationPolicyVersion)
				assert.Equal(t, tc.expected.CertificationProfiles, result.CertificationProfiles)
				assert.Equal(t, tc.expected.CertificationRequirementsVersion, result.CertificationRequirementsVersion)
				assert.Equal(t, tc.expected.SunsetDate, result.SunsetDate)
				assert.Equal(t, tc.expected.FIPSRevision, result.FIPSRevision)
				assert.Equal(t, tc.expected.FIPSPhysicalSecurityLevel, result.FIPSPhysicalSecurityLevel)

				if tc.expectedURL != "" {
					assert.NotNil(t, result.URL)
					assert.Equal(t, tc.expectedURL, result.URL.String())
				}
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestAuthenticatorGetInfoJSON_Parse(t *testing.T) {
	testCases := []struct {
		name string
		have AuthenticatorGetInfoJSON
		err  string
	}{
		{
			name: "ShouldFailInvalidAAGUID",
			have: AuthenticatorGetInfoJSON{
				AaGUID: "not-a-uuid",
			},
			err: "error occurred parsing AAGUID value: invalid UUID length: 10",
		},
		{
			name: "ShouldSucceedMinimal",
			have: AuthenticatorGetInfoJSON{},
		},
		{
			name: "ShouldSucceedWithAAGUID",
			have: AuthenticatorGetInfoJSON{
				AaGUID: "2369d4d0-13ce-48cb-9f26-f7ed8c9a6068",
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := tc.have.Parse()

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func timePtr(t time.Time) *time.Time {
	return &t
}

func TestStatementJSONDecodesCurrentSpecMembers(t *testing.T) {
	// The member names are decoded from the JWT claims by mapstructure using the json tags, so an incorrect tag leaves
	// the field silently unset rather than failing. These names are taken from the Metadata Statement v3.1.1 and the
	// authenticatorGetInfo response of CTAP 2.3.
	raw := map[string]any{
		"description": "test",
		"cxConfigURL": "https://example.com/cx",
		"authenticatorGetInfo": map[string]any{
			"attestationFormats":          []any{"packed", "tpm"},
			"uvCountSinceLastPinEntry":    3,
			"longTouchForReset":           true,
			"encIdentifier":               "aGVsbG8=",
			"transportsForReset":          []any{"usb", "nfc"},
			"pinComplexityPolicy":         true,
			"pinComplexityPolicyURL":      "aHR0cHM6Ly9leGFtcGxlLmNvbQ==",
			"maxPINLength":                63,
			"encCredStoreState":           "d29ybGQ=",
			"authenticatorConfigCommands": []any{1, 2},
		},
	}

	var statement StatementJSON

	decoder, err := mapstructure.NewDecoder(&mapstructure.DecoderConfig{Result: &statement, TagName: "json"})
	require.NoError(t, err)
	require.NoError(t, decoder.Decode(raw))

	assert.Equal(t, "https://example.com/cx", statement.CredentialExchangeConfigURL)

	info := statement.AuthenticatorGetInfo

	assert.Equal(t, []string{"packed", "tpm"}, info.AttestationFormats)
	assert.Equal(t, uint(3), info.UvCountSinceLastPinEntry)
	assert.True(t, info.LongTouchForReset)
	assert.Equal(t, "aGVsbG8=", info.EncIdentifier)
	assert.Equal(t, []string{"usb", "nfc"}, info.TransportsForReset)
	assert.True(t, info.PinComplexityPolicy)
	assert.Equal(t, "aHR0cHM6Ly9leGFtcGxlLmNvbQ==", info.PinComplexityPolicyURL)
	assert.Equal(t, uint(63), info.MaxPINLength)
	assert.Equal(t, "d29ybGQ=", info.EncCredStoreState)
	assert.Equal(t, []uint{1, 2}, info.AuthenticatorConfigCommands)

	parsed, err := statement.Parse()
	require.NoError(t, err)

	require.NotNil(t, parsed.CredentialExchangeConfigURL)
	assert.Equal(t, "https://example.com/cx", parsed.CredentialExchangeConfigURL.String())
	assert.Equal(t, []string{"packed", "tpm"}, parsed.AuthenticatorGetInfo.AttestationFormats)
	assert.True(t, parsed.AuthenticatorGetInfo.LongTouchForReset)
	assert.Equal(t, uint(63), parsed.AuthenticatorGetInfo.MaxPINLength)
	assert.Equal(t, []uint{1, 2}, parsed.AuthenticatorGetInfo.AuthenticatorConfigCommands)
}
