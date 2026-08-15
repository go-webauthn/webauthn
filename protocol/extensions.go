package protocol

import (
	"encoding/json"
	"fmt"
	"slices"
	"strings"
)

// Extensions are discussed in §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn-3/#extensions).

// For a list of defined extensions, see §10. Defined Extensions
// (https://www.w3.org/TR/webauthn-3/#sctn-defined-extensions).

// extensionNameModelled reports whether key matches one of names, comparing case-insensitively. It is shared by the
// extension input codec (extensions_inputs.go) and the extension output codec (extensions_outputs.go) so a JSON
// member whose key differs from a modelled name only by case is treated consistently by both: as a collision when
// marshalling Extra, and as the modelled field rather than an Extra entry when unmarshalling.
//
// The case-insensitive comparison mirrors the fallback [encoding/json] itself uses when it cannot find a struct
// field whose tag exactly matches a JSON object key. Without this, the two codecs would delete only the
// exact-case name from the untyped member map while encoding/json bound the case-insensitive variant to the typed
// field, leaving the same member present in both the typed field and Extra.
func extensionNameModelled(names []string, key string) bool {
	_, modelled := extensionNameCanonical(names, key)

	return modelled
}

// extensionNameCanonical resolves key to the entry of names it matches case-insensitively, so a member whose key
// differs from a modelled name only by case is reported under the identifier the rest of the package uses. It
// backs extensionNameModelled so the two cannot disagree about what counts as a match.
func extensionNameCanonical(names []string, key string) (name string, modelled bool) {
	if index := slices.IndexFunc(names, func(name string) bool { return strings.EqualFold(name, key) }); index >= 0 {
		return names[index], true
	}

	return "", false
}

// extensionsMarshalExtra merges extra into the already marshalled form of the modelled members and returns the
// combined JSON object. It backs the MarshalJSON of both the extension inputs and the extension outputs, which
// differ only in their identifier list and in the label their errors carry. Marshalling always routes through a map
// so the key ordering does not depend on whether extra is populated.
//
// The collision check is against names rather than the marshalled members so a modelled extension is rejected even
// when its field is zero and therefore absent from the output. Routing a modelled extension through the untyped bag
// would bypass the typed model and be silently dropped on the way back in. The comparison is case-insensitive
// because encoding/json would bind a case-variant key to the modelled field on the way back in; see
// extensionNameModelled.
func extensionsMarshalExtra(data []byte, names []string, extra map[string]any, label string) (out []byte, err error) {
	var members map[string]json.RawMessage

	if err = json.Unmarshal(data, &members); err != nil {
		return nil, err
	}

	for key, value := range extra {
		if extensionNameModelled(names, key) {
			return nil, fmt.Errorf("error marshalling %s: extra extension %q collides with a modelled extension", label, key)
		}

		if members[key], err = json.Marshal(value); err != nil {
			return nil, fmt.Errorf("error marshalling %s: extra extension %q: %w", label, key, err)
		}
	}

	return json.Marshal(members)
}

const (
	// ExtensionAppID is the FIDO AppID Extension identifier. It is used during authentication to allow credentials
	// registered via the legacy FIDO U2F JavaScript API to be used with WebAuthn.
	//
	// Specification: §10.1.1. FIDO AppID Extension (https://www.w3.org/TR/webauthn-3/#sctn-appid-extension)
	ExtensionAppID = "appid"

	// ExtensionAppIDExclude is the FIDO AppID Exclusion Extension identifier. It is used during registration to
	// exclude credentials previously registered via the legacy FIDO U2F JavaScript API.
	//
	// Specification: §10.1.2. FIDO AppID Exclusion Extension (https://www.w3.org/TR/webauthn-3/#sctn-appid-exclude-extension)
	ExtensionAppIDExclude = "appidExclude"

	// ExtensionCredProps is the Credential Properties Extension identifier. It is used during registration to
	// request that the client report properties of the newly created credential.
	//
	// Specification: §10.1.3. Credential Properties Extension (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension)
	ExtensionCredProps = "credProps"

	// ExtensionPRF is the Pseudo-random function Extension identifier. It is used during registration and
	// authentication to evaluate a PRF scoped to the credential.
	//
	// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
	ExtensionPRF = "prf"

	// ExtensionLargeBlob is the Large blob storage Extension identifier. It is used during registration to request
	// support, and during authentication to read or write opaque data associated with a credential.
	//
	// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
	ExtensionLargeBlob = "largeBlob"

	// ExtensionRemoteClientDataJSON is the Remote Client Data JSON Extension identifier. It is set by a remote
	// desktop web client, not by a Relying Party. A Relying Party receiving this output should understand that the
	// local client delegated every RP ID and origin check to a remote host.
	//
	// This extension is not defined by WebAuthn Level 3. It exists only in the Editor's Draft and is modelled here
	// ahead of ratification, so its definition may change before it is published in a Recommendation.
	//
	// Specification: §10.1.6. Remote Client Data JSON extension (https://w3c.github.io/webauthn/#sctn-remote-client-data-json-extension)
	ExtensionRemoteClientDataJSON = "remoteClientDataJSON"
)

// The following extension identifiers are defined by CTAP 2.1 and CTAP 2.2 and registered in the IANA "WebAuthn
// Extension Identifiers" registry established by RFC8809. They are not defined by WebAuthn Level 3, however several
// clients forward them as extension inputs.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
const (
	// ExtensionCredentialProtectionPolicy requests a credential protection policy at registration.
	ExtensionCredentialProtectionPolicy = "credentialProtectionPolicy"

	// ExtensionEnforceCredentialProtectionPolicy requires that the requested credential protection policy is
	// honoured, failing the ceremony if the authenticator cannot satisfy it.
	ExtensionEnforceCredentialProtectionPolicy = "enforceCredentialProtectionPolicy"

	// ExtensionCredProtect is the credProtect extension's authenticator-output identifier, carried in the
	// authenticator data's extension outputs. It is deliberately distinct from
	// ExtensionCredentialProtectionPolicy, which is the client-facing input identifier used by the
	// create() extensions member; authenticators echo this abbreviated identifier, not that one.
	ExtensionCredProtect = "credProtect"

	// ExtensionMinPinLength requests the authenticator's current minimum PIN length at registration.
	ExtensionMinPinLength = "minPinLength"

	// ExtensionCredBlob requests that a small blob is stored with the credential at registration.
	ExtensionCredBlob = "credBlob"

	// ExtensionGetCredBlob requests the blob stored with the credential at authentication.
	ExtensionGetCredBlob = "getCredBlob"

	// ExtensionLargeBlobKey is the CTAP largeBlobKey extension identifier. It is deliberately NOT modelled by
	// this library: it has no client extension input and no client extension output, so there is nothing for a
	// Relying Party to send or receive. CTAP 2.1 §12.3 states "Client extension input / output / processing:
	// None" and that the extension "is not suitable to be directly exposed to RPs". The key itself is returned
	// as the largeBlobKey (0x05) member of the CTAP response structure, not as a client extension and not as an
	// authenticator data extension, and it is driven by the client platform rather than the Relying Party.
	//
	// Do not add a typed member or a dedicated functional option for this. A caller with a non-browser CTAP
	// client that genuinely needs to set it can use webauthn.WithExtension with this identifier, which routes it
	// through the untyped extension inputs verbatim.
	ExtensionLargeBlobKey = "largeBlobKey"

	// ExtensionHMACCreateSecret requests that the authenticator provisions an HMAC secret at registration.
	ExtensionHMACCreateSecret = "hmacCreateSecret"

	// ExtensionHMACGetSecret requests evaluation of the HMAC secret at authentication.
	ExtensionHMACGetSecret = "hmacGetSecret"

	// ExtensionHMACSecret is the CTAP hmac-secret extension's authenticator-output identifier. It is carried in
	// the authenticator data's extension outputs, as a boolean at registration and as a byte string at
	// authentication. It is deliberately distinct from ExtensionHMACCreateSecret and ExtensionHMACGetSecret,
	// which are the client-facing input identifiers used by the create()/get() extensions member; authenticators
	// echo this hyphenated identifier, not those, in their extension outputs.
	ExtensionHMACSecret = "hmac-secret"

	// ExtensionUVM requests the user verification methods used for the operation.
	ExtensionUVM = "uvm"
)

// LargeBlobSupport represents the LargeBlobSupport IDL enumeration used by the large blob storage extension during
// registration.
//
// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
type LargeBlobSupport string

const (
	// LargeBlobSupportRequired indicates the credential MUST support the large blob storage extension. The client
	// fails the ceremony when no eligible authenticator supports it.
	LargeBlobSupportRequired LargeBlobSupport = "required"

	// LargeBlobSupportPreferred indicates the credential SHOULD support the large blob storage extension.
	LargeBlobSupportPreferred LargeBlobSupport = "preferred"
)

// CredentialProtectionPolicy represents the credential protection policy values of the CTAP credProtect extension.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
type CredentialProtectionPolicy string

const (
	// CredentialProtectionPolicyUserVerificationOptional is credProtect value 0x01.
	CredentialProtectionPolicyUserVerificationOptional CredentialProtectionPolicy = "userVerificationOptional"

	// CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList is credProtect value 0x02.
	CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList CredentialProtectionPolicy = "userVerificationOptionalWithCredentialIDList"

	// CredentialProtectionPolicyUserVerificationRequired is credProtect value 0x03.
	CredentialProtectionPolicyUserVerificationRequired CredentialProtectionPolicy = "userVerificationRequired"
)

// PRFValues represents the AuthenticationExtensionsPRFValuesJSON IDL. The byte values are conveyed to the client
// base64url encoded.
//
// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
type PRFValues struct {
	First  URLEncodedBase64 `json:"first"`
	Second URLEncodedBase64 `json:"second,omitempty"`
}

// IsZero returns true when no PRF value is set. It is used by the encoding/json omitzero tag option.
func (v PRFValues) IsZero() bool {
	return len(v.First) == 0 && len(v.Second) == 0
}

// PRFInputs represents the AuthenticationExtensionsPRFInputsJSON IDL.
//
// Every member is optional. A zero value is the bare availability probe, i.e. the "prf":{} input a Relying Party
// sends at registration to learn whether the pseudo-random function is available for the credential; the client
// answers with the 'enabled' output. This is why [AuthenticationExtensions.PRF] is a pointer while its
// [LargeBlobInputs] and [HMACGetSecretInputs] siblings are not.
//
// EvalByCredential is only valid during authentication; the client throws a NotSupportedError when it is present
// during registration. Its keys are base64url encoded credential IDs which MUST each match an entry of the
// allowed credentials.
//
// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
type PRFInputs struct {
	Eval             PRFValues            `json:"eval,omitzero"`
	EvalByCredential map[string]PRFValues `json:"evalByCredential,omitempty"`
}

// IsZero returns true when no PRF input is set. It is used by the encoding/json omitzero tag option.
func (i PRFInputs) IsZero() bool {
	return i.Eval.IsZero() && len(i.EvalByCredential) == 0
}

// LargeBlobInputs represents the AuthenticationExtensionsLargeBlobInputsJSON IDL. Support is only valid during
// registration; Read and Write are only valid during authentication and are mutually exclusive.
//
// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
type LargeBlobInputs struct {
	Support LargeBlobSupport `json:"support,omitempty"`
	Read    bool             `json:"read,omitempty"`
	Write   URLEncodedBase64 `json:"write,omitempty"`
}

// IsZero returns true when no large blob input is set. It is used by the encoding/json omitzero tag option.
func (i LargeBlobInputs) IsZero() bool {
	return i.Support == "" && !i.Read && len(i.Write) == 0
}

// HMACGetSecretInputs represents the inputs of the CTAP hmac-secret extension during authentication.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
type HMACGetSecretInputs struct {
	Salt1 URLEncodedBase64 `json:"salt1"`
	Salt2 URLEncodedBase64 `json:"salt2,omitempty"`
}

// IsZero returns true when no salt is set. It is used by the encoding/json omitzero tag option.
func (i HMACGetSecretInputs) IsZero() bool {
	return len(i.Salt1) == 0 && len(i.Salt2) == 0
}
