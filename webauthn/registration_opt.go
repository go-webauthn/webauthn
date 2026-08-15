package webauthn

import "github.com/go-webauthn/webauthn/protocol"

// WithCredentialParameters adjusts the credential parameters in the registration options.
//
// Specification: §5.4. Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-pubkeycredparams)
func WithCredentialParameters(credentialParams []protocol.CredentialParameter) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.Parameters = credentialParams

		return nil
	}
}

// WithExclusions adjusts the non-default parameters regarding credentials to exclude from registration.
//
// Specification: §5.4. Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-excludecredentials)
func WithExclusions(excludeList []protocol.CredentialDescriptor) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.CredentialExcludeList = excludeList

		return nil
	}
}

// WithAuthenticatorSelection adjusts the non-default parameters regarding the authenticator to select during
// registration.
//
// Specification: §5.4. Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-authenticatorselection)
//
// Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria)
func WithAuthenticatorSelection(authenticatorSelection protocol.AuthenticatorSelection) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.AuthenticatorSelection = authenticatorSelection

		return nil
	}
}

// WithResidentKeyRequirement sets both the resident key and require resident key protocol options.
//
// Specification: §5.4. Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-authenticatorselection)
//
// Specification: §5.4.4. Authenticator Selection Criteria (https://www.w3.org/TR/webauthn/#dictdef-authenticatorselectioncriteria)
func WithResidentKeyRequirement(requirement protocol.ResidentKeyRequirement) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.AuthenticatorSelection.ResidentKey = requirement

		switch requirement {
		case protocol.ResidentKeyRequirementRequired:
			cco.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyRequired()
		default:
			cco.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyNotRequired()
		}

		return nil
	}
}

// WithPublicKeyCredentialHints adjusts the non-default hints for credential types to select during registration.
//
// WebAuthn Level 3.
//
// Specification: §5.4. Parameters for Credential Generation (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-hints)
func WithPublicKeyCredentialHints(hints []protocol.PublicKeyCredentialHints) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.Hints = hints

		return nil
	}
}

// WithConveyancePreference adjusts the non-default parameters regarding whether the authenticator should attest to the
// credential.
//
// Specification: §5.4. Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialcreationoptions-attestation)
func WithConveyancePreference(preference protocol.ConveyancePreference) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.Attestation = preference

		return nil
	}
}

// WithAttestationFormats adjusts the non-default formats for credential types to select during registration.
//
// WebAuthn Level 3.
//
// Specification: §5.4. Parameters for Credential Generation (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialcreationoptions-attestationformats)
func WithAttestationFormats(formats []protocol.AttestationFormat) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.AttestationFormats = formats

		return nil
	}
}

// WithAppIdExcludeExtension sets the specified appid as the FIDO AppID Exclusion Extension input. The option
// itself always sets it; [WebAuthn.BeginRegistration] then discards it unless the CredentialExcludeList contains a
// credential with the fido-u2f attestation format, which is what makes the result independent of the order the
// options were supplied in.
//
// Specification: §10.1.2. FIDO AppID Exclusion Extension (https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension)
//
// Deprecated: use [WithExtensions] with [WithExtensionAppIDExclude], which is order-independent with respect to
// [WithExclusions].
func WithAppIdExcludeExtension(appid string) RegistrationOption {
	return WithExtensions(WithExtensionAppIDExclude(appid))
}

// WithRegistrationRelyingPartyID sets the relying party id for the registration.
func WithRegistrationRelyingPartyID(id string) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.RelyingParty.ID = id

		return nil
	}
}

// WithRegistrationOrigin binds this registration ceremony to a single origin, which [WebAuthn.CreateCredential]
// verifies the collected client data against in place of every origin in [Config.RPOrigins]. A Relying Party which
// serves several origins can therefore hold a ceremony to the origin it was begun at, so a response collected at one
// of its other origins does not complete it.
//
// The origin must be one of those configured in [Config.RPOrigins]; the option narrows that set and can't widen it,
// so a value which is not configured fails at [WebAuthn.BeginRegistration] rather than at the Finish step. It must
// also be a http or https origin. An opaque origin such as 'android:apk-key-hash:...' is only ever conveyed in the
// response and so can't be known when the ceremony begins; those configured in [Config.RPOpaqueOrigins] remain
// acceptable while a ceremony is bound, as a Relying Party which accepts native clients cannot tell them apart from
// browser clients in advance.
//
// The binding covers the ceremony origin only. A topOrigin is verified against [Config.RPTopOrigins] under the
// configured [protocol.TopOriginVerificationMode] as usual.
//
// Specification: §7.1. Registering a New Credential, step 9 (https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
func WithRegistrationOrigin(origin string) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.Origin = origin

		return nil
	}
}

// WithRegistrationRelyingPartyName sets the relying party name for the registration.
func WithRegistrationRelyingPartyName(name string) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.RelyingParty.Name = name

		return nil
	}
}
