package protocol

import (
	"strings"
)

// ClientCapability represents an entry of the ClientCapability enumeration, which names a capability a client may
// report through PublicKeyCredential.getClientCapabilities(). A Relying Party typically has the client send the
// result to the server so it can pick a ceremony the client can actually complete, for example offering conditional
// mediation only where it is available.
//
// The IDL types the keys of the reported record as DOMString rather than as this enumeration, so a value which is
// not one of the constants below is not an error: a client may report a capability ratified after this release, and
// it also reports one key per supported extension, named by [ExtensionClientCapability]. Values are therefore
// deliberately not validated, which is the same call [PublicKeyCredentialHints] makes for the same reason.
//
// What a client reports is advisory. It is a statement by software the Relying Party does not control, sent over a
// channel the Relying Party does not control, so it belongs in flow selection and never in a security decision. The
// ceremony verification steps are what establish security properties.
//
// WebAuthn Level 3.
//
// Specification: §5.8.7. Client Capability Enumeration (https://www.w3.org/TR/webauthn-3/#enum-clientCapability)
type ClientCapability string

const (
	// ClientCapabilityConditionalCreate indicates the client supports conditionally mediated registration, i.e. a
	// create() call with a mediation of conditional.
	ClientCapabilityConditionalCreate ClientCapability = "conditionalCreate"

	// ClientCapabilityConditionalGet indicates the client supports conditionally mediated authentication, i.e. a
	// get() call with a mediation of conditional, which is what backs autofill of a passkey.
	ClientCapabilityConditionalGet ClientCapability = "conditionalGet"

	// ClientCapabilityHybridTransport indicates the client supports the hybrid transport, i.e. using a nearby
	// device such as a phone as an authenticator.
	ClientCapabilityHybridTransport ClientCapability = "hybridTransport"

	// ClientCapabilityPasskeyPlatformAuthenticator indicates a passkey capable platform authenticator is available,
	// whether attached to the client device or reachable over the hybrid transport.
	ClientCapabilityPasskeyPlatformAuthenticator ClientCapability = "passkeyPlatformAuthenticator"

	// ClientCapabilityUserVerifyingPlatformAuthenticator indicates a user verifying platform authenticator is
	// available on the client device.
	ClientCapabilityUserVerifyingPlatformAuthenticator ClientCapability = "userVerifyingPlatformAuthenticator"

	// ClientCapabilityRelatedOrigins indicates the client supports Related Origin Requests, i.e. that it will read
	// the document a Relying Party serves at [WellKnownPathWebAuthn].
	//
	// Specification: §5.11. Related Origin Requests (https://www.w3.org/TR/webauthn-3/#sctn-related-origins)
	ClientCapabilityRelatedOrigins ClientCapability = "relatedOrigins"

	// ClientCapabilitySignalAllAcceptedCredentials indicates the client supports the
	// signalAllAcceptedCredentials() method.
	ClientCapabilitySignalAllAcceptedCredentials ClientCapability = "signalAllAcceptedCredentials"

	// ClientCapabilitySignalCurrentUserDetails indicates the client supports the signalCurrentUserDetails() method.
	ClientCapabilitySignalCurrentUserDetails ClientCapability = "signalCurrentUserDetails"

	// ClientCapabilitySignalUnknownCredential indicates the client supports the signalUnknownCredential() method.
	ClientCapabilitySignalUnknownCredential ClientCapability = "signalUnknownCredential"
)

// ClientCapabilityExtensionPrefix is prepended to an extension identifier to name the capability under which a
// client reports support for that extension. Build such a capability with [ExtensionClientCapability] and take one
// apart with [ClientCapability.Extension] rather than concatenating this constant directly.
//
// Specification: §5.1.7. Availability of client capabilities (https://www.w3.org/TR/webauthn-3/#sctn-getClientCapabilities)
const ClientCapabilityExtensionPrefix = "extension:"

// ExtensionClientCapability returns the capability under which a client reports support for the extension with the
// given identifier, for example [ExtensionPRF] becoming "extension:prf".
//
// An identifier which already carries [ClientCapabilityExtensionPrefix] is returned unchanged rather than prefixed
// twice, so a caller which passes a key read straight out of a record gets the key back. An empty identifier, with
// or without the prefix, yields an empty capability: the prefix alone names no extension.
func ExtensionClientCapability(identifier string) ClientCapability {
	identifier = strings.TrimPrefix(identifier, ClientCapabilityExtensionPrefix)

	if identifier == "" {
		return ""
	}

	return ClientCapability(ClientCapabilityExtensionPrefix + identifier)
}

// Extension reports whether this capability names an extension, and if so the identifier of that extension. It is
// the inverse of [ExtensionClientCapability], and is how a Relying Party walking a whole record tells the extension
// keys apart from the capabilities of [ClientCapabilities].
//
// The bare prefix with no identifier after it names no extension and reports false.
func (c ClientCapability) Extension() (identifier string, ok bool) {
	if identifier, ok = strings.CutPrefix(string(c), ClientCapabilityExtensionPrefix); !ok || identifier == "" {
		return "", false
	}

	return identifier, true
}

// ClientCapabilities represents the record a client returns from PublicKeyCredential.getClientCapabilities(), which
// maps a capability to whether the client currently supports it.
//
// It is a map rather than a struct so a capability this release does not model, including every extension key,
// survives a round trip through the Relying Party's own transport rather than being dropped on the way in.
//
// Read it with [ClientCapabilities.Supported] rather than by indexing. A key which is absent from the record is not
// the same as a key reported false: the specification allows no assumption about the availability of a feature the
// client did not mention, and indexing a Go map cannot express that difference.
//
// Specification: §5.1.7. Availability of client capabilities (https://www.w3.org/TR/webauthn-3/#sctn-getClientCapabilities)
type ClientCapabilities map[ClientCapability]bool

// Supported reports whether the client stated support for the given capability, and whether it mentioned the
// capability at all. A reported value of false means the client stated it does not support the capability; a
// reported value of false with ok false means the client said nothing, which licenses no conclusion either way.
func (c ClientCapabilities) Supported(capability ClientCapability) (supported, reported bool) {
	supported, reported = c[capability]

	return supported, reported
}

// Extension reports whether the client stated support for the extension with the given identifier, under the same
// two value contract as [ClientCapabilities.Supported]. The identifier is resolved with [ExtensionClientCapability],
// so an argument which already carries [ClientCapabilityExtensionPrefix] is accepted as it stands.
//
// An empty identifier reports nothing, since the prefix alone names no extension.
func (c ClientCapabilities) Extension(identifier string) (supported, reported bool) {
	capability := ExtensionClientCapability(identifier)
	if capability == "" {
		return false, false
	}

	return c.Supported(capability)
}
