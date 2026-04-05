package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
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
			name: "ShouldFailInvalidCxpConfigURL",
			have: StatementJSON{
				Description:                       "test",
				CredentialExportProtocolConfigURL: "://bad",
			},
			err: "error occurred parsing statement with description 'test': error occurred parsing cxp config url value: parse \"://bad\": missing protocol scheme",
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
		name string
		have BiometricStatusReportJSON
		err  string
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

func TestStatusReportJSON_Parse(t *testing.T) {
	testCases := []struct {
		name     string
		have     StatusReportJSON
		expected StatusReport
		err      string
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
			name: "ShouldSucceedMinimal",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
			},
			expected: StatusReport{
				Status:        "",
				EffectiveDate: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
			},
		},
		{
			name: "ShouldSucceedWithSunsetDate",
			have: StatusReportJSON{
				EffectiveDate: "2025-01-01",
				SunsetDate:    "2026-06-01",
			},
			expected: StatusReport{
				EffectiveDate: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
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
				EffectiveDate:                    time.Date(2025, 3, 15, 0, 0, 0, 0, time.UTC),
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

				if tc.have.URL != "" {
					assert.NotNil(t, result.URL)
					assert.Equal(t, tc.have.URL, result.URL.String())
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
