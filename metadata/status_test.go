package metadata

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// now is the reference point used by the status report tests. Reports are placed relative to it so that the effective
// and sunset date handling is exercised deterministically.
var now = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC)

func date(y int, m time.Month, d int) *time.Time {
	v := time.Date(y, m, d, 0, 0, 0, 0, time.UTC)

	return &v
}

func TestValidateStatusReportsAt(t *testing.T) {
	testCases := []struct {
		name      string
		reports   []StatusReport
		desired   []AuthenticatorStatus
		undesired []AuthenticatorStatus
		err       string
	}{
		{
			name:      "ShouldReturnNilForEmptyDesiredAndUndesired",
			reports:   []StatusReport{{Status: FidoCertified}},
			desired:   nil,
			undesired: nil,
		},
		{
			name:      "ShouldReturnNilForEmptyDesiredAndEmptyReports",
			reports:   nil,
			desired:   nil,
			undesired: []AuthenticatorStatus{Revoked},
		},
		{
			name:      "ShouldReturnNilWhenNoUndesiredPresent",
			reports:   []StatusReport{{Status: FidoCertified}},
			desired:   []AuthenticatorStatus{FidoCertified},
			undesired: []AuthenticatorStatus{Revoked},
		},
		{
			name:      "ShouldFailWhenUndesiredPresent",
			reports:   []StatusReport{{Status: Revoked}},
			desired:   nil,
			undesired: []AuthenticatorStatus{Revoked},
			err:       "The following undesired status reports were present: REVOKED",
		},
		{
			name:      "ShouldFailWithMultipleUndesiredPresent",
			reports:   []StatusReport{{Status: Revoked}, {Status: AttestationKeyCompromise}},
			desired:   nil,
			undesired: []AuthenticatorStatus{Revoked, AttestationKeyCompromise},
			err:       "The following undesired status reports were present: REVOKED, ATTESTATION_KEY_COMPROMISE",
		},
		{
			name:      "ShouldNotRepeatDuplicateUndesiredStatuses",
			reports:   []StatusReport{{Status: Revoked}, {Status: Revoked}},
			undesired: []AuthenticatorStatus{Revoked},
			err:       "The following undesired status reports were present: REVOKED",
		},

		// The desired statuses are a set of acceptable current statuses.
		{
			name:    "ShouldAcceptCurrentStatusAmongDesired",
			reports: []StatusReport{{Status: FidoCertified}, {Status: FidoCertifiedL1}},
			desired: []AuthenticatorStatus{FidoCertified, FidoCertifiedL1},
		},
		{
			// The authenticator held FIDO_CERTIFIED historically but the current status is FIDO_CERTIFIED_L1.
			name:    "ShouldRejectSupersededDesiredStatus",
			reports: []StatusReport{{Status: FidoCertified}, {Status: FidoCertifiedL1}},
			desired: []AuthenticatorStatus{FidoCertified},
			err:     "the current status report 'FIDO_CERTIFIED_L1' was not one of the desired statuses: FIDO_CERTIFIED",
		},
		{
			// A revoked authenticator must not satisfy a desired status naming a certification it formerly held.
			name:    "ShouldRejectRevokedDespiteFormerCertification",
			reports: []StatusReport{{Status: FidoCertifiedL2}, {Status: Revoked}},
			desired: []AuthenticatorStatus{FidoCertifiedL2},
			err:     "the current status report 'REVOKED' was not one of the desired statuses: FIDO_CERTIFIED_L2",
		},
		{
			name:    "ShouldFailWhenDesiredAbsent",
			reports: []StatusReport{{Status: NotFidoCertified}},
			desired: []AuthenticatorStatus{FidoCertified},
			err:     "the current status report 'NOT_FIDO_CERTIFIED' was not one of the desired statuses: FIDO_CERTIFIED",
		},
		{
			name:      "ShouldFailWhenBothUndesiredPresentAndDesiredUnsatisfied",
			reports:   []StatusReport{{Status: Revoked}},
			desired:   []AuthenticatorStatus{FidoCertified},
			undesired: []AuthenticatorStatus{Revoked},
			err:       "The following undesired status reports were present: REVOKED; the current status report 'REVOKED' was not one of the desired statuses: FIDO_CERTIFIED",
		},
		{
			name:    "ShouldFailWhenNoReportsAtAll",
			reports: nil,
			desired: []AuthenticatorStatus{FidoCertifiedL1},
			err:     "no status report was in effect so none of the desired statuses could be satisfied: FIDO_CERTIFIED_L1",
		},

		// Reports which are not in effect are excluded entirely.
		{
			name:      "ShouldIgnoreUndesiredReportPastItsSunsetDate",
			reports:   []StatusReport{{Status: UserVerificationBypass, SunsetDate: date(2025, 1, 1)}, {Status: FidoCertifiedL2}},
			undesired: []AuthenticatorStatus{UserVerificationBypass},
		},
		{
			name:      "ShouldHonourUndesiredReportBeforeItsSunsetDate",
			reports:   []StatusReport{{Status: UserVerificationBypass, SunsetDate: date(2025, 12, 1)}},
			undesired: []AuthenticatorStatus{UserVerificationBypass},
			err:       "The following undesired status reports were present: USER_VERIFICATION_BYPASS",
		},
		{
			name:      "ShouldIgnoreUndesiredReportNotYetEffective",
			reports:   []StatusReport{{Status: FidoCertifiedL2}, {Status: Revoked, EffectiveDate: date(2025, 12, 1)}},
			undesired: []AuthenticatorStatus{Revoked},
		},
		{
			name:      "ShouldHonourUndesiredReportAlreadyEffective",
			reports:   []StatusReport{{Status: FidoCertifiedL2}, {Status: Revoked, EffectiveDate: date(2025, 1, 1)}},
			undesired: []AuthenticatorStatus{Revoked},
			err:       "The following undesired status reports were present: REVOKED",
		},
		{
			// The pending revocation is not in effect so the certification remains current.
			name:    "ShouldUseLatestEffectiveReportAsCurrent",
			reports: []StatusReport{{Status: FidoCertifiedL2}, {Status: Revoked, EffectiveDate: date(2025, 12, 1)}},
			desired: []AuthenticatorStatus{FidoCertifiedL2},
		},
		{
			name:    "ShouldFailWhenEveryReportHasSunset",
			reports: []StatusReport{{Status: FidoCertifiedL2, SunsetDate: date(2025, 1, 1)}},
			desired: []AuthenticatorStatus{FidoCertifiedL2},
			err:     "no status report was in effect so none of the desired statuses could be satisfied: FIDO_CERTIFIED_L2",
		},
		{
			// Effective dates take precedence over document order so a blob which does not list reports oldest first
			// still resolves the correct current status.
			name:    "ShouldPreferEffectiveDateOverDocumentOrder",
			reports: []StatusReport{{Status: Revoked, EffectiveDate: date(2025, 3, 1)}, {Status: FidoCertifiedL2, EffectiveDate: date(2020, 1, 1)}},
			desired: []AuthenticatorStatus{FidoCertifiedL2},
			err:     "the current status report 'REVOKED' was not one of the desired statuses: FIDO_CERTIFIED_L2",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStatusReportsAt(tc.reports, tc.desired, tc.undesired, now)

			if tc.err != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestValidateStatusReportsUsesCurrentTime(t *testing.T) {
	// The exported wrapper must apply the same effective and sunset date handling relative to the current time.
	reports := []StatusReport{
		{Status: Revoked, SunsetDate: date(2020, 1, 1)},
		{Status: FidoCertifiedL2},
	}

	assert.NoError(t, ValidateStatusReports(reports, []AuthenticatorStatus{FidoCertifiedL2}, DefaultUndesiredAuthenticatorStatuses()))

	pending := []StatusReport{
		{Status: FidoCertifiedL2},
		{Status: Revoked, EffectiveDate: date(2999, 1, 1)},
	}

	assert.NoError(t, ValidateStatusReports(pending, nil, DefaultUndesiredAuthenticatorStatuses()))
}

func TestStatusReportInEffectAt(t *testing.T) {
	testCases := []struct {
		name     string
		report   StatusReport
		expected bool
	}{
		{
			name:     "ShouldBeInEffectWithoutDates",
			report:   StatusReport{Status: FidoCertifiedL1},
			expected: true,
		},
		{
			name:     "ShouldBeInEffectAfterEffectiveDate",
			report:   StatusReport{EffectiveDate: date(2025, 1, 1)},
			expected: true,
		},
		{
			name:     "ShouldBeInEffectOnEffectiveDate",
			report:   StatusReport{EffectiveDate: date(2025, 6, 1)},
			expected: true,
		},
		{
			name:     "ShouldNotBeInEffectBeforeEffectiveDate",
			report:   StatusReport{EffectiveDate: date(2025, 6, 2)},
			expected: false,
		},
		{
			name:     "ShouldNotBeInEffectOnSunsetDate",
			report:   StatusReport{SunsetDate: date(2025, 6, 1)},
			expected: false,
		},
		{
			name:     "ShouldNotBeInEffectAfterSunsetDate",
			report:   StatusReport{SunsetDate: date(2025, 5, 1)},
			expected: false,
		},
		{
			name:     "ShouldBeInEffectBeforeSunsetDate",
			report:   StatusReport{SunsetDate: date(2025, 6, 2)},
			expected: true,
		},
		{
			name:     "ShouldBeInEffectWithinWindow",
			report:   StatusReport{EffectiveDate: date(2025, 1, 1), SunsetDate: date(2025, 12, 1)},
			expected: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.report.InEffectAt(now))
		})
	}
}

func TestCurrentStatusReportAt(t *testing.T) {
	testCases := []struct {
		name     string
		reports  []StatusReport
		expected *AuthenticatorStatus
	}{
		{
			name:     "ShouldReturnNilForNoReports",
			reports:  nil,
			expected: nil,
		},
		{
			name:     "ShouldReturnNilWhenAllReportsExcluded",
			reports:  []StatusReport{{Status: FidoCertifiedL1, SunsetDate: date(2025, 1, 1)}},
			expected: nil,
		},
		{
			name:     "ShouldReturnLastReportInDocumentOrder",
			reports:  []StatusReport{{Status: NotFidoCertified}, {Status: FidoCertifiedL1}},
			expected: statusPtr(FidoCertifiedL1),
		},
		{
			name:     "ShouldPreferGreatestEffectiveDate",
			reports:  []StatusReport{{Status: FidoCertifiedL2, EffectiveDate: date(2025, 3, 1)}, {Status: NotFidoCertified, EffectiveDate: date(2019, 1, 1)}},
			expected: statusPtr(FidoCertifiedL2),
		},
		{
			name:     "ShouldResolveTiesToTheLaterReport",
			reports:  []StatusReport{{Status: NotFidoCertified, EffectiveDate: date(2025, 3, 1)}, {Status: FidoCertifiedL2, EffectiveDate: date(2025, 3, 1)}},
			expected: statusPtr(FidoCertifiedL2),
		},
		{
			name:     "ShouldSkipReportsNotYetEffective",
			reports:  []StatusReport{{Status: FidoCertifiedL2}, {Status: Revoked, EffectiveDate: date(2025, 12, 1)}},
			expected: statusPtr(FidoCertifiedL2),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			current := CurrentStatusReportAt(tc.reports, now)

			if tc.expected == nil {
				assert.Nil(t, current)
			} else {
				require.NotNil(t, current)
				assert.Equal(t, *tc.expected, current.Status)
			}
		})
	}
}

func TestEffectiveStatusReports(t *testing.T) {
	reports := []StatusReport{
		{Status: NotFidoCertified},
		{Status: UserVerificationBypass, SunsetDate: date(2025, 1, 1)},
		{Status: FidoCertifiedL1, EffectiveDate: date(2025, 1, 1)},
		{Status: Revoked, EffectiveDate: date(2025, 12, 1)},
	}

	effective := EffectiveStatusReports(reports, now)

	require.Len(t, effective, 2)
	assert.Equal(t, NotFidoCertified, effective[0].Status)
	assert.Equal(t, FidoCertifiedL1, effective[1].Status)
}

func statusPtr(status AuthenticatorStatus) *AuthenticatorStatus {
	return &status
}
