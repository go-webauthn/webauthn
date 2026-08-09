package metadata

import (
	"fmt"
	"strings"
	"time"
)

// InEffectAt returns true if this [StatusReport] is in effect at the given time.
//
// A report which has an effective date in the future has not come into effect yet, and a report which has reached its
// sunset date has expired. An absent effective date means the report is in effect while present, and an absent sunset
// date means it has no scheduled expiry.
//
// See: https://fidoalliance.org/specs/mds/fido-metadata-service-v3.1.1-ps-20260105.html#sctn-stat-rep
func (r StatusReport) InEffectAt(at time.Time) bool {
	if r.EffectiveDate != nil && r.EffectiveDate.After(at) {
		return false
	}

	if r.SunsetDate != nil && !r.SunsetDate.After(at) {
		return false
	}

	return true
}

// EffectiveStatusReports returns the subset of the given [StatusReport] values which are in effect at the given time,
// preserving their original order. See [StatusReport.InEffectAt] for the rules applied.
func EffectiveStatusReports(reports []StatusReport, at time.Time) (effective []StatusReport) {
	for _, report := range reports {
		if report.InEffectAt(at) {
			effective = append(effective, report)
		}
	}

	return effective
}

// CurrentStatusReportAt returns the [StatusReport] which reflects the current status of the authenticator at the given
// time, or nil if no report is in effect. See [currentStatusReport] for how the current report is selected.
func CurrentStatusReportAt(reports []StatusReport, at time.Time) (current *StatusReport) {
	return currentStatusReport(EffectiveStatusReports(reports, at))
}

// currentStatusReport returns the report reflecting the current status from a set of reports already known to be in
// effect, or nil if there are none.
//
// MDS3 requires that the latest entry reflects the current status, so the last element wins by default. Where both
// candidates carry an effective date that date is preferred over the document order, which keeps the selection correct
// for a blob whose reports are not listed oldest first. Ties resolve to the later element.
func currentStatusReport(effective []StatusReport) (current *StatusReport) {
	for i := range effective {
		report := &effective[i]

		if current == nil || current.EffectiveDate == nil || report.EffectiveDate == nil {
			current = report

			continue
		}

		if !report.EffectiveDate.Before(*current.EffectiveDate) {
			current = report
		}
	}

	return current
}

// ValidateStatusReports checks a list of [StatusReport] structs against a list of desired and undesired
// [AuthenticatorStatus] values as at the current time. See [ValidateStatusReportsAt] for the validation performed.
func ValidateStatusReports(reports []StatusReport, desired, undesired []AuthenticatorStatus) (err error) {
	return ValidateStatusReportsAt(reports, desired, undesired, time.Now())
}

// ValidateStatusReportsAt checks a list of [StatusReport] structs against a list of desired and undesired
// [AuthenticatorStatus] values as at the given time. If the reports satisfy the desired statuses and contain none of
// the undesired statuses then no error is returned, otherwise an error describing the issue is returned.
//
// Reports which are not in effect at the given time are excluded from consideration entirely, i.e. those with an
// effective date in the future and those which have reached their sunset date.
//
// The desired statuses are matched against the current status only, and are treated as a set of acceptable statuses of
// which one must match. MDS3 requires that the latest report reflects the current status, so an authenticator formerly
// certified at some level but since revoked does not satisfy a desired status naming that certification level.
//
// The undesired statuses are matched against every report in effect rather than the current one alone. Statuses such as
// [AttestationKeyCompromise] and [UserKeyPhysicalCompromise] describe a weakness discovered in the authenticator model
// which a later report does not retract; the sunset date honored above is the mechanism by which such a report stops
// applying.
//
// Note that a compromise reported against a specific attestation certificate, i.e. where [StatusReport.Certificate] or
// [StatusReport.BatchCertificate] is set, applies only to that batch of authenticators. This function has no visibility
// of the attestation statement being validated, so it conservatively treats such a report as applying to every
// authenticator of the model.
func ValidateStatusReportsAt(reports []StatusReport, desired, undesired []AuthenticatorStatus, at time.Time) (err error) {
	if len(desired) == 0 && len(undesired) == 0 {
		return nil
	}

	effective := EffectiveStatusReports(reports, at)

	var present []string

	if len(undesired) != 0 {
		seen := make(map[AuthenticatorStatus]struct{}, len(undesired))

		for _, report := range effective {
			if _, ok := seen[report.Status]; ok {
				continue
			}

			if hasStatus(report.Status, undesired) {
				seen[report.Status] = struct{}{}

				present = append(present, string(report.Status))
			}
		}
	}

	var (
		current     *StatusReport
		unsatisfied bool
	)

	if len(desired) != 0 {
		current = currentStatusReport(effective)

		unsatisfied = current == nil || !hasStatus(current.Status, desired)
	}

	switch {
	case len(present) == 0 && !unsatisfied:
		return nil
	case len(present) != 0 && !unsatisfied:
		return &Error{
			Type:    "invalid_status",
			Details: fmt.Sprintf("The following undesired status reports were present: %s", strings.Join(present, ", ")),
		}
	case len(present) == 0:
		return &Error{
			Type:    "invalid_status",
			Details: describeDesiredUnsatisfied(current, desired),
		}
	default:
		return &Error{
			Type:    "invalid_status",
			Details: fmt.Sprintf("The following undesired status reports were present: %s; %s", strings.Join(present, ", "), describeDesiredUnsatisfied(current, desired)),
		}
	}
}

// hasStatus returns true if the given status is a member of the given values.
func hasStatus(status AuthenticatorStatus, values []AuthenticatorStatus) bool {
	for _, value := range values {
		if value == status {
			return true
		}
	}

	return false
}

// describeDesiredUnsatisfied renders the reason the desired statuses were not satisfied by the current status report.
func describeDesiredUnsatisfied(current *StatusReport, desired []AuthenticatorStatus) string {
	statuses := make([]string, len(desired))

	for i, status := range desired {
		statuses[i] = string(status)
	}

	if current == nil {
		return fmt.Sprintf("no status report was in effect so none of the desired statuses could be satisfied: %s", strings.Join(statuses, ", "))
	}

	return fmt.Sprintf("the current status report '%s' was not one of the desired statuses: %s", current.Status, strings.Join(statuses, ", "))
}
