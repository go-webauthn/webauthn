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

// WithRegistrationRelyingPartyName sets the relying party name for the registration.
func WithRegistrationRelyingPartyName(name string) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) error {
		cco.RelyingParty.Name = name

		return nil
	}
}
