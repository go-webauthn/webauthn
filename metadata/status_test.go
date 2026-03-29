package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateStatusReports(t *testing.T) {
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
			name:    "ShouldReturnNilWhenAllDesiredPresent",
			reports: []StatusReport{{Status: FidoCertified}, {Status: FidoCertifiedL1}},
			desired: []AuthenticatorStatus{FidoCertified},
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
			name:    "ShouldFailWhenDesiredAbsent",
			reports: []StatusReport{{Status: NotFidoCertified}},
			desired: []AuthenticatorStatus{FidoCertified},
			err:     "The following desired status reports were absent: FIDO_CERTIFIED",
		},
		{
			name:      "ShouldFailWhenBothUndesiredPresentAndDesiredAbsent",
			reports:   []StatusReport{{Status: Revoked}},
			desired:   []AuthenticatorStatus{FidoCertified},
			undesired: []AuthenticatorStatus{Revoked},
			err:       "The following undesired status reports were present: REVOKED; the following desired status reports were absent: FIDO_CERTIFIED",
		},
		{
			name:      "ShouldReturnNilWithMultipleDesiredAllPresent",
			reports:   []StatusReport{{Status: FidoCertified}, {Status: FidoCertifiedL1}},
			desired:   []AuthenticatorStatus{FidoCertified, FidoCertifiedL1},
			undesired: []AuthenticatorStatus{Revoked},
		},
		{
			name:      "ShouldFailWithMultipleUndesiredPresent",
			reports:   []StatusReport{{Status: Revoked}, {Status: AttestationKeyCompromise}},
			desired:   nil,
			undesired: []AuthenticatorStatus{Revoked, AttestationKeyCompromise},
			err:       "The following undesired status reports were present: REVOKED, ATTESTATION_KEY_COMPROMISE",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateStatusReports(tc.reports, tc.desired, tc.undesired)

			if tc.err != "" {
				require.Error(t, err)
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}
