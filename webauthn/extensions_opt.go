package webauthn

import (
	"fmt"
	"strings"

	"github.com/go-webauthn/webauthn/protocol"
)

// ExtensionOption configures a single WebAuthn extension. The ceremony is supplied so an option can reject use in
// a ceremony the extension does not apply to.
//
// Options are applied through [WithExtensions] for a registration ceremony and [WithAssertionExtensions] for an
// authentication ceremony, which is how one definition serves both.
type ExtensionOption func(e *protocol.AuthenticationExtensions, c protocol.CeremonyType) error

// WithExtensions applies the given extension options to a registration ceremony.
//
// Specification: §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn-3/#extensions)
func WithExtensions(opts ...ExtensionOption) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		return applyExtensionOptions(&cco.Extensions, protocol.CreateCeremony, opts)
	}
}

// WithAssertionExtensions applies the given extension options to an authentication ceremony.
//
// Specification: §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn-3/#extensions)
func WithAssertionExtensions(opts ...ExtensionOption) LoginOption {
	return func(pkcro *protocol.PublicKeyCredentialRequestOptions) error {
		return applyExtensionOptions(&pkcro.Extensions, protocol.AssertCeremony, opts)
	}
}

// applyExtensionOptions applies each option in order and then validates the resulting inputs against the ceremony.
// The trailing validation is what constrains [WithExtensionInputs], which accepts a whole structure and therefore
// cannot be checked by the individual options.
func applyExtensionOptions(exts *protocol.AuthenticationExtensions, ceremony protocol.CeremonyType, opts []ExtensionOption) (err error) {
	for _, opt := range opts {
		if err = opt(exts, ceremony); err != nil {
			return err
		}
	}

	return exts.Validate(ceremony)
}

// forCeremony returns an ExtensionOption which applies the given function only when the ceremony matches, and
// which otherwise reports that the extension does not apply.
func forCeremony(name string, ceremony protocol.CeremonyType, apply func(e *protocol.AuthenticationExtensions)) ExtensionOption {
	return func(e *protocol.AuthenticationExtensions, c protocol.CeremonyType) error {
		if c != ceremony {
			if ceremony == protocol.CreateCeremony {
				return fmt.Errorf("extension %q is a registration extension but was provided for an authentication ceremony", name)
			}

			return fmt.Errorf("extension %q is an authentication extension but was provided for a registration ceremony", name)
		}

		apply(e)

		return nil
	}
}

// forAnyCeremony returns an ExtensionOption which applies to both ceremonies.
func forAnyCeremony(apply func(e *protocol.AuthenticationExtensions)) ExtensionOption {
	return func(e *protocol.AuthenticationExtensions, _ protocol.CeremonyType) error {
		apply(e)

		return nil
	}
}

// WithExtensionInputs sets the extension inputs wholesale. It is the counterpart to
// [protocol.ParseAuthenticationExtensions] for callers migrating from the previous map-based representation, and
// replaces any inputs set by earlier options.
//
// The inputs are validated against the ceremony by the enclosing [WithExtensions] or [WithAssertionExtensions].
//
// The AppID and AppIDExclude members are subject to the same unconditional pruning as [WithExtensionAppID] and
// [WithExtensionAppIDExclude]: [WebAuthn.BeginLogin] and [WebAuthn.BeginRegistration] discard them when the
// relevant credential list contains no fido-u2f credential. There is no path that bypasses that.
func WithExtensionInputs(in protocol.AuthenticationExtensions) ExtensionOption {
	return forAnyCeremony(func(e *protocol.AuthenticationExtensions) {
		*e = in
	})
}

// WithExtension sets an extension input this library does not model, carrying the value through to the client
// verbatim. An identifier this library does model is rejected; use its dedicated option instead so the value is
// typed and the ceremony is checked.
//
// The identifier comparison is case-insensitive, matching both JSON codecs. An exact comparison would accept a
// case variant such as "CredProps", place it in the untyped inputs, report it from
// [protocol.AuthenticationExtensions.Requested], and then fail the whole options object at marshalling time with a
// collision error, rather than naming the dedicated option here.
func WithExtension(name string, value any) ExtensionOption {
	return func(e *protocol.AuthenticationExtensions, _ protocol.CeremonyType) error {
		for modelled, suffix := range extensionOptionSuffixes {
			if strings.EqualFold(modelled, name) {
				return fmt.Errorf("extension %q is modelled by this library; use WithExtension%s instead of WithExtension", name, suffix)
			}
		}

		if e.Extra == nil {
			e.Extra = map[string]any{}
		}

		e.Extra[name] = value

		return nil
	}
}

// suffixProtectionPolicy is the option-name suffix shared by the two credProtect identifiers, because a single
// option sets both the policy and its enforcement flag.
const suffixProtectionPolicy = "CredentialProtectionPolicy"

// extensionOptionSuffixes maps each extension identifier which has a dedicated option to the name suffix of that
// option. [WithExtension] rejects any identifier present here and names the option the caller should use instead.
var extensionOptionSuffixes = map[string]string{
	protocol.ExtensionAppID:                             "AppID",
	protocol.ExtensionAppIDExclude:                      "AppIDExclude",
	protocol.ExtensionCredProps:                         "CredProps",
	protocol.ExtensionPRF:                               "PRF, WithExtensionPRFSupport or WithExtensionPRFByCredential",
	protocol.ExtensionLargeBlob:                         "LargeBlobSupport, WithExtensionLargeBlobRead or WithExtensionLargeBlobWrite",
	protocol.ExtensionRemoteClientDataJSON:              "RemoteClientDataJSON",
	protocol.ExtensionCredentialProtectionPolicy:        suffixProtectionPolicy,
	protocol.ExtensionEnforceCredentialProtectionPolicy: suffixProtectionPolicy,
	protocol.ExtensionMinPinLength:                      "MinPinLength",
	protocol.ExtensionCredBlob:                          "CredBlob",
	protocol.ExtensionGetCredBlob:                       "GetCredBlob",
	protocol.ExtensionHMACCreateSecret:                  "HMACCreateSecret",
	protocol.ExtensionHMACGetSecret:                     "HMACGetSecret",
	protocol.ExtensionUVM:                               "UVM",
}

// The following options apply to both ceremonies.

// WithExtensionPRFSupport requests the pseudo-random function extension without supplying any salt to evaluate,
// which is the bare "prf":{} input. It asks the client whether the pseudo-random function is available for the
// credential; the answer arrives as the 'enabled' client extension output and is recorded on the credential record
// as [CredentialExtensions.PRFEnabled]. It is the canonical registration-time probe, though it is accepted for both
// ceremonies.
//
// It leaves any values set by [WithExtensionPRF] or [WithExtensionPRFByCredential] untouched, so ordering relative
// to those options does not matter.
//
// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
func WithExtensionPRFSupport() ExtensionOption {
	return forAnyCeremony(func(e *protocol.AuthenticationExtensions) {
		if e.PRF == nil {
			e.PRF = &protocol.PRFInputs{}
		}
	})
}

// WithExtensionPRF requests evaluation of the pseudo-random function for the credential. A zero eval requests the
// extension without any salt to evaluate, which is equivalent to [WithExtensionPRFSupport].
//
// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
func WithExtensionPRF(eval protocol.PRFValues) ExtensionOption {
	return forAnyCeremony(func(e *protocol.AuthenticationExtensions) {
		if e.PRF == nil {
			e.PRF = &protocol.PRFInputs{}
		}

		e.PRF.Eval = eval
	})
}

// WithExtensionRemoteClientDataJSON sets the remote client data JSON. This extension is intended for a remote
// desktop web client and a Relying Party should not normally set it; a Relying Party which receives the matching
// output should understand that the local client delegated every RP ID and origin check to a remote host.
//
// This extension is not defined by WebAuthn Level 3. It exists only in the Editor's Draft and is modelled here ahead
// of ratification, so its definition may change before it is published in a Recommendation.
//
// Specification: §10.1.6. Remote Client Data JSON extension (https://w3c.github.io/webauthn/#sctn-remote-client-data-json-extension)
func WithExtensionRemoteClientDataJSON(clientDataJSON string) ExtensionOption {
	return forAnyCeremony(func(e *protocol.AuthenticationExtensions) {
		e.RemoteClientDataJSON = clientDataJSON
	})
}

// WithExtensionUVM requests the user verification methods used for the operation.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func WithExtensionUVM() ExtensionOption {
	return forAnyCeremony(func(e *protocol.AuthenticationExtensions) {
		e.UVM = true
	})
}

// The following options apply to a registration ceremony only.

// WithExtensionCredProps requests that the client reports the properties of the newly created credential.
//
// Specification: §10.1.3. Credential Properties Extension (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension)
func WithExtensionCredProps() ExtensionOption {
	return forCeremony(protocol.ExtensionCredProps, protocol.CreateCeremony, func(e *protocol.AuthenticationExtensions) {
		e.CredProps = true
	})
}

// WithExtensionAppIDExclude sets the FIDO AppID used to exclude credentials registered through the legacy FIDO U2F
// JavaScript API. The value is discarded by [WebAuthn.BeginRegistration] when the exclude list contains no
// credential with the fido-u2f attestation format, so the ordering of this option relative to [WithExclusions]
// does not matter.
//
// Specification: §10.1.2. FIDO AppID Exclusion Extension (https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension)
func WithExtensionAppIDExclude(appid string) ExtensionOption {
	return forCeremony(protocol.ExtensionAppIDExclude, protocol.CreateCeremony, func(e *protocol.AuthenticationExtensions) {
		e.AppIDExclude = appid
	})
}

// WithExtensionLargeBlobSupport requests large blob storage support for the credential.
//
// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
func WithExtensionLargeBlobSupport(support protocol.LargeBlobSupport) ExtensionOption {
	return forCeremony(protocol.ExtensionLargeBlob, protocol.CreateCeremony, func(e *protocol.AuthenticationExtensions) {
		e.LargeBlob.Support = support
	})
}

// WithExtensionCredentialProtectionPolicy requests a credential protection policy, optionally requiring that the
// authenticator honours it.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func WithExtensionCredentialProtectionPolicy(policy protocol.CredentialProtectionPolicy, enforce bool) ExtensionOption {
	return forCeremony(protocol.ExtensionCredentialProtectionPolicy, protocol.CreateCeremony, func(e *protocol.AuthenticationExtensions) {
		e.CredentialProtectionPolicy = policy
		e.EnforceCredentialProtectionPolicy = enforce
	})
}

// WithExtensionMinPinLength requests the authenticator's current minimum PIN length.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func WithExtensionMinPinLength() ExtensionOption {
	return forCeremony(protocol.ExtensionMinPinLength, protocol.CreateCeremony, func(e *protocol.AuthenticationExtensions) {
		e.MinPinLength = true
	})
}

// WithExtensionCredBlob requests that the given blob is stored with the credential.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func WithExtensionCredBlob(blob []byte) ExtensionOption {
	return forCeremony(protocol.ExtensionCredBlob, protocol.CreateCeremony, func(e *protocol.AuthenticationExtensions) {
		e.CredBlob = blob
	})
}

// WithExtensionHMACCreateSecret requests that the authenticator provisions an HMAC secret for the credential.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func WithExtensionHMACCreateSecret() ExtensionOption {
	return forCeremony(protocol.ExtensionHMACCreateSecret, protocol.CreateCeremony, func(e *protocol.AuthenticationExtensions) {
		e.HMACCreateSecret = true
	})
}

// The following options apply to an authentication ceremony only.

// WithExtensionAppID sets the FIDO AppID for credentials registered through the legacy FIDO U2F JavaScript API.
// The value is discarded by [WebAuthn.BeginLogin] when the allowed credentials contain no credential with the
// fido-u2f attestation format, so the ordering of this option relative to [WithAllowedCredentials] does not matter.
//
// Specification: §10.1.1. FIDO AppID Extension (https://www.w3.org/TR/webauthn-3/#sctn-appid-extension)
func WithExtensionAppID(appid string) ExtensionOption {
	return forCeremony(protocol.ExtensionAppID, protocol.AssertCeremony, func(e *protocol.AuthenticationExtensions) {
		e.AppID = appid
	})
}

// WithExtensionPRFByCredential requests per-credential evaluation of the pseudo-random function. The keys of
// byCredential are base64url encoded credential IDs which MUST each match an entry of the allowed credentials.
// A non-nil fallback is used for allowed credentials with no entry in the map; a nil fallback leaves any eval
// value set by an earlier [WithExtensionPRF] untouched rather than clearing it.
//
// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
func WithExtensionPRFByCredential(byCredential map[string]protocol.PRFValues, fallback *protocol.PRFValues) ExtensionOption {
	return forCeremony(protocol.ExtensionPRF, protocol.AssertCeremony, func(e *protocol.AuthenticationExtensions) {
		if e.PRF == nil {
			e.PRF = &protocol.PRFInputs{}
		}

		e.PRF.EvalByCredential = byCredential

		if fallback != nil {
			e.PRF.Eval = *fallback
		}
	})
}

// WithExtensionLargeBlobRead requests the blob stored with the credential.
//
// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
func WithExtensionLargeBlobRead() ExtensionOption {
	return forCeremony(protocol.ExtensionLargeBlob, protocol.AssertCeremony, func(e *protocol.AuthenticationExtensions) {
		e.LargeBlob.Read = true
	})
}

// WithExtensionLargeBlobWrite requests that the given blob is written to the credential. This is mutually
// exclusive with [WithExtensionLargeBlobRead].
//
// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
func WithExtensionLargeBlobWrite(blob []byte) ExtensionOption {
	return forCeremony(protocol.ExtensionLargeBlob, protocol.AssertCeremony, func(e *protocol.AuthenticationExtensions) {
		e.LargeBlob.Write = blob
	})
}

// WithExtensionGetCredBlob requests the blob stored with the credential.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func WithExtensionGetCredBlob() ExtensionOption {
	return forCeremony(protocol.ExtensionGetCredBlob, protocol.AssertCeremony, func(e *protocol.AuthenticationExtensions) {
		e.GetCredBlob = true
	})
}

// WithExtensionHMACGetSecret requests evaluation of the credential's HMAC secret with the given salts. Salt2 may
// be nil.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
func WithExtensionHMACGetSecret(salt1, salt2 []byte) ExtensionOption {
	return forCeremony(protocol.ExtensionHMACGetSecret, protocol.AssertCeremony, func(e *protocol.AuthenticationExtensions) {
		e.HMACGetSecret = protocol.HMACGetSecretInputs{Salt1: salt1, Salt2: salt2}
	})
}
