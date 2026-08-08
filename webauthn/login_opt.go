package webauthn

import "github.com/go-webauthn/webauthn/protocol"

// WithChallenge overrides the random challenge that [WebAuthn.BeginLogin] would otherwise generate for this
// ceremony. The supplied value is used verbatim.
//
// The only safe reason to call this is when the relying party needs to record the challenge in a server-side store
// before the ceremony is initiated; for example to maintain a set of previously-issued challenges so it can
// reject a replay that reuses one. Generating the challenge inside a separate step lets the RP persist it
// atomically before it is ever handed to the client.
//
// If you have that need, the supplied challenge MUST be produced by [protocol.CreateChallenge] (32 bytes from
// crypto/rand). Do not use timestamps, counters, UUIDs, hashed user inputs, or any other deterministic or
// partially-predictable source; these defeat the cryptographic guarantees the challenge provides and open the
// ceremony to replay and guessing attacks. [WebAuthn.BeginLogin] enforces a minimum length of
// [protocol.MinimumChallengeLength] bytes, but that check is a backstop only and is not a substitute for using a
// CSPRNG.
//
// If you do not have a specific persistence requirement, do not use this function; let the library generate the
// challenge automatically.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-challenge)
//
// Specification: §13.4.3. Cryptographic Challenges (https://www.w3.org/TR/webauthn/#sctn-cryptographic-challenges)
func WithChallenge(challenge []byte) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) error {
		cco.Challenge = challenge

		return nil
	}
}

// WithLoginRelyingPartyID sets the Relying Party ID for this particular login.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-rpid)
func WithLoginRelyingPartyID(id string) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) error {
		cco.RelyingPartyID = id

		return nil
	}
}

// WithAllowedCredentials adjusts the allowed credentials via a slice of [protocol.CredentialDescriptor] values,
// discussed in the included specification sections with user-supplied values.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-allowcredentials)
//
// Specification: §5.10.3. Credential Descriptor (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor)
func WithAllowedCredentials(allowList []protocol.CredentialDescriptor) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) error {
		cco.AllowedCredentials = allowList

		return nil
	}
}

// WithUserVerification adjusts the user verification preference by providing a [protocol.UserVerificationRequirement].
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-userverification)
func WithUserVerification(userVerification protocol.UserVerificationRequirement) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) error {
		cco.UserVerification = userVerification

		return nil
	}
}

// WithAssertionPublicKeyCredentialHints adjusts the non-default hints for credential types to select during login by
// providing a slice of [protocol.PublicKeyCredentialHints].
//
// WebAuthn Level 3.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn-3/#dom-publickeycredentialrequestoptions-hints)
func WithAssertionPublicKeyCredentialHints(hints []protocol.PublicKeyCredentialHints) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) error {
		cco.Hints = hints

		return nil
	}
}

// WithAppIdExtension automatically includes the specified appid if the AllowedCredentials contains a credential
// with the fido-u2f attestation format.
//
// Specification: §5.5. Options for Assertion Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialrequestoptions-extensions)
//
// Specification: §10.1.1. FIDO AppID Extension (https://www.w3.org/TR/webauthn-3/#sctn-appid-extension)
//
// Deprecated: use [WithAssertionExtensions] with [WithExtensionAppID], which is order-independent with respect to
// [WithAllowedCredentials].
func WithAppIdExtension(appid string) LoginOption {
	return WithAssertionExtensions(WithExtensionAppID(appid))
}
