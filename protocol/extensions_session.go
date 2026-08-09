package protocol

import (
	"errors"
	"fmt"
	"maps"
	"slices"
	"strings"
)

// SessionExtensions is the subset of [AuthenticationExtensions] a Relying Party must persist between the begin and
// finish steps of a ceremony in order to verify the extension outputs it receives.
//
// The per-ceremony PRF salts and the large blob write payload are deliberately excluded. The salts are secrets with
// no verification role and the payload can be large; both are represented by their identifier in Requested.
type SessionExtensions struct {
	// Requested lists the extension identifiers the Relying Party asked for, as reported by
	// [AuthenticationExtensions.Requested]. An extension output whose identifier is absent from this list was not
	// solicited.
	Requested []string `json:"requested,omitempty"`

	// AppID is the FIDO AppID Extension input, required to determine the Relying Party ID of a credential
	// registered through the legacy FIDO U2F JavaScript API.
	AppID string `json:"appid,omitempty"`

	// AppIDExclude is the FIDO AppID Exclusion Extension input.
	AppIDExclude string `json:"appidExclude,omitempty"`

	// LargeBlob is the large blob support requirement requested at registration. A value of
	// [LargeBlobSupportRequired] is asserted against the extension output.
	LargeBlob LargeBlobSupport `json:"largeBlob,omitempty"`

	// LargeBlobRead records that a large blob read was requested at authentication.
	LargeBlobRead bool `json:"largeBlobRead,omitempty"`

	// LargeBlobWrite records that a large blob write was requested at authentication. Only the intent is recorded;
	// the payload itself is excluded because it can be large and has no verification role beyond this flag.
	LargeBlobWrite bool `json:"largeBlobWrite,omitempty"`

	// CredentialProtectionPolicy is the CTAP credProtect policy requested at registration. It is asserted against
	// the authenticator extension output when EnforceCredentialProtectionPolicy is set.
	CredentialProtectionPolicy CredentialProtectionPolicy `json:"credentialProtectionPolicy,omitempty"`

	// EnforceCredentialProtectionPolicy records that the requested credential protection policy must be honoured.
	EnforceCredentialProtectionPolicy bool `json:"enforceCredentialProtectionPolicy,omitempty"`

	// CredBlob records that a blob was submitted for storage with the credential at registration. As with
	// LargeBlobWrite only the intent is recorded, because the blob is Relying Party data with no verification role
	// beyond this flag.
	CredBlob bool `json:"credBlob,omitempty"`

	// Extra carries the inputs of extensions this library does not model, so a Relying Party can verify the
	// outputs of its own extensions. Whatever is placed here is persisted verbatim; keep it small.
	Extra map[string]any `json:"extra,omitempty"`
}

// IsZero returns true when nothing needs to be persisted. It is used by the encoding/json omitzero tag option.
func (e SessionExtensions) IsZero() bool {
	return len(e.Requested) == 0 && e.AppID == "" && e.AppIDExclude == "" && e.LargeBlob == "" && !e.LargeBlobRead &&
		!e.LargeBlobWrite && e.CredentialProtectionPolicy == "" && !e.EnforceCredentialProtectionPolicy &&
		!e.CredBlob && len(e.Extra) == 0
}

// Session returns the subset of these inputs that must be persisted in the session for the finish step of the
// ceremony to verify the extension outputs.
//
// Extra is cloned so the persisted session and the live options do not share a backing map; mutating the inputs
// after the begin step must not retroactively change what the finish step verifies against.
//
// The clone is shallow. A value inside Extra which is itself a reference type stays shared with the inputs, so a
// Relying Party which mutates a nested map or slice after the begin step does change what the finish step sees.
// Extra holds Relying Party data rather than anything an attacker supplies, and a deep clone of an arbitrary value
// cannot be done without either reflection or a serialisation round trip, so the boundary is documented instead of
// widened. Persisting the session, as a Relying Party is required to do between the two steps, is itself a
// serialisation and does not carry the sharing with it.
func (e AuthenticationExtensions) Session() SessionExtensions {
	return SessionExtensions{
		Requested:                         e.Requested(),
		AppID:                             e.AppID,
		AppIDExclude:                      e.AppIDExclude,
		LargeBlob:                         e.LargeBlob.Support,
		LargeBlobRead:                     e.LargeBlob.Read,
		LargeBlobWrite:                    len(e.LargeBlob.Write) != 0,
		CredentialProtectionPolicy:        e.CredentialProtectionPolicy,
		EnforceCredentialProtectionPolicy: e.EnforceCredentialProtectionPolicy,
		CredBlob:                          len(e.CredBlob) != 0,
		Extra:                             maps.Clone(e.Extra),
	}
}

// UnsolicitedOutputPolicy determines how a client extension output that the Relying Party did not request is
// handled during the finish step of a ceremony.
type UnsolicitedOutputPolicy int

const (
	// UnsolicitedOutputPolicyReject fails the ceremony when the client returns an extension output the Relying
	// Party did not request. This is the zero value and therefore the default.
	UnsolicitedOutputPolicyReject UnsolicitedOutputPolicy = iota

	// UnsolicitedOutputPolicyIgnore accepts and ignores extension outputs the Relying Party did not request. Use
	// this only when a client is known to return outputs unprompted.
	UnsolicitedOutputPolicyIgnore
)

// Verify checks these client extension outputs against the extensions recorded in the session.
//
// Two rules are enforced. First, every present output must correspond to an extension the Relying Party requested;
// keys of [AuthenticationExtensionsClientOutputs.Extra] participate on equal terms with the modelled members. This
// subsumes ceremony applicability, because an output that cannot be requested for a ceremony cannot have been
// requested at all. Second, a registration that required large blob support must have received it.
//
// Every problem found is reported rather than only the first. The result is an [Error] whose details name every
// problem and whose cause is the [errors.Join] of them, so [errors.As] and [errors.Is] reach each one individually.
//
// A ceremony which is neither [CreateCeremony] nor [AssertCeremony] is treated as a registration, so an unexpected
// value fails closed against the required large blob support assertion rather than skipping it.
//
// The appid value path is not handled here; see [ParsedPublicKeyCredential.GetAppID].
//
// Specification: §7.1. Registering a New Credential (https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
//
// Specification: §7.2. Verifying an Authentication Assertion (https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
func (o AuthenticationExtensionsClientOutputs) Verify(session SessionExtensions, ceremony CeremonyType, policy UnsolicitedOutputPolicy) error {
	var errs []error

	if policy != UnsolicitedOutputPolicyIgnore {
		for _, name := range o.Present() {
			if !slices.Contains(session.Requested, name) {
				errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("Client returned the %q extension output which was not requested", name)))
			}
		}
	}

	// The guard is written against AssertCeremony rather than CreateCeremony so an unrecognised ceremony still has
	// the required-support assertion applied, matching the policy guard above. Verify is exported, so the ceremony
	// is not necessarily one this package produced.
	if ceremony != AssertCeremony {
		if session.LargeBlob == LargeBlobSupportRequired {
			if o.LargeBlob == nil || o.LargeBlob.Supported == nil || !*o.LargeBlob.Supported {
				errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with support required but the client did not report it as supported", ExtensionLargeBlob)))
			}
		}
	} else {
		errs = append(errs, o.verifyLargeBlobAssertion(session)...)
	}

	if len(errs) == 0 {
		return nil
	}

	// errors.Join always wraps, even for a single error, so returning it directly would make this the only failure
	// path out of the finish step which does not yield an *Error. The joined error is kept as the cause, so
	// errors.As and errors.Is still reach each individual problem, and every problem is also named in the details.
	joined := errors.Join(errs...)

	return ErrBadRequest.
		WithDetails(fmt.Sprintf("Error validating the client extension outputs: %s", strings.ReplaceAll(joined.Error(), "\n", "; "))).
		WithError(joined)
}

// verifyLargeBlobAssertion checks the large blob outputs of an authentication ceremony against the read or write
// that was requested. The unsolicited output check only establishes that the extension was requested at all; the
// read and write arms produce disjoint outputs, so which one was asked for still has to be asserted.
//
// A write that the client reports as not performed is an error. The assertion itself is cryptographically sound at
// this point, so the alternative is to return a successful login to a Relying Party which believes its blob was
// stored when it was not.
//
// A read is not required to produce a blob: a credential with nothing stored yields an empty output, which is a
// legitimate result rather than a failure.
//
// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
func (o AuthenticationExtensionsClientOutputs) verifyLargeBlobAssertion(session SessionExtensions) (errs []error) {
	switch {
	case session.LargeBlobWrite:
		if o.LargeBlob == nil || o.LargeBlob.Written == nil {
			errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with a blob to write but the client did not report whether it was written", ExtensionLargeBlob)))
		} else if !*o.LargeBlob.Written {
			errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with a blob to write but the client reported it was not written", ExtensionLargeBlob)))
		}

		if o.LargeBlob != nil && len(o.LargeBlob.Blob) != 0 {
			errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with a blob to write but the client returned a blob it read", ExtensionLargeBlob)))
		}
	case session.LargeBlobRead:
		if o.LargeBlob != nil && o.LargeBlob.Written != nil {
			errs = append(errs, ErrBadRequest.WithDetails(fmt.Sprintf("The %q extension was requested with a blob to read but the client reported the outcome of a write", ExtensionLargeBlob)))
		}
	}

	return errs
}
