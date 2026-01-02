package webauthn

import "github.com/go-webauthn/webauthn/protocol"

// WithChallenge overrides the default random challenge with a user supplied value.
// In order to prevent replay attacks, the challenges MUST contain enough entropy to make guessing them infeasible.
// Challenges SHOULD therefore be at least 16 bytes long.
// This function is EXPERIMENTAL and can be removed without warning.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-challenge)
//
// Specification: §13.4.3. Cryptographic Challenges (https://www.w3.org/TR/webauthn/#sctn-cryptographic-challenges)
func WithChallenge(challenge []byte) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Challenge = challenge
	}
}

// WithLoginRelyingPartyID sets the Relying Party ID for this particular login.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-rpid)
func WithLoginRelyingPartyID(id string) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.RelyingPartyID = id
	}
}

// WithAllowedCredentials adjusts the allowed credentials via a slice of [protocol.CredentialDescriptor] values,
// discussed in the included specification sections with user-supplied values.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-allowcredentials)
//
// Specification: §5.10.3. Credential Descriptor (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor)
func WithAllowedCredentials(allowList []protocol.CredentialDescriptor) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.AllowedCredentials = allowList
	}
}

// WithUserVerification adjusts the user verification preference by providing a [protocol.UserVerificationRequirement].
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-userverification)
func WithUserVerification(userVerification protocol.UserVerificationRequirement) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.UserVerification = userVerification
	}
}

// WithAssertionPublicKeyCredentialHints adjusts the non-default hints for credential types to select during login by
// providing a slice of [protocol.PublicKeyCredentialHints].
//
// WebAuthn Level 3.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints)
func WithAssertionPublicKeyCredentialHints(hints []protocol.PublicKeyCredentialHints) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Hints = hints
	}
}

// WithAssertionExtensions adjusts the requested extensions by providing a [protocol.AuthenticationExtensions].
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-extensions)
func WithAssertionExtensions(extensions protocol.AuthenticationExtensions) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Extensions = extensions
	}
}

// WithAppIdExtension automatically includes the specified appid if the AllowedCredentials contains a credential
// with the type `fido-u2f`.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-extensions)
func WithAppIdExtension(appid string) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		for _, credential := range cco.AllowedCredentials {
			if credential.AttestationType == protocol.CredentialTypeFIDOU2F {
				if cco.Extensions == nil {
					cco.Extensions = map[string]any{}
				}

				cco.Extensions[protocol.ExtensionAppID] = appid

				break
			}
		}
	}
}
