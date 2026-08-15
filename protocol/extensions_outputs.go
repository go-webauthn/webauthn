package protocol

import (
	"bytes"
	"encoding/json"
	"fmt"
	"maps"
	"slices"
)

// jsonNull is the encoded form of a JSON null, compared against a raw member value to detect a modelled extension
// output the client returned without a value.
var jsonNull = []byte("null")

// AuthenticationExtensionsClientOutputs represents the AuthenticationExtensionsClientOutputs IDL, returned by the
// client after a create() or get() call.
//
// Every modelled member is a pointer so an absent value is distinguishable from a false or empty one; the
// unsolicited output check performed by [AuthenticationExtensionsClientOutputs.Verify] depends on that distinction.
//
// A JSON member whose key matches a modelled name only by case (e.g. "AppID" for "appid") is bound to that
// modelled field, not collected into [AuthenticationExtensionsClientOutputs.Extra]: encoding/json resolves the
// case-insensitive match during the first decoding pass, before UnmarshalJSON ever sees the untyped member map. If
// such a member's value has the wrong type for the modelled field, unmarshalling fails outright rather than
// falling back to Extra. encoding/json (v1, the only version this module may use) offers no way to defer that
// binding.
//
// Specification: §5.9. Authentication Extensions Client Outputs (https://www.w3.org/TR/webauthn-3/#iface-authentication-extensions-client-outputs)
type AuthenticationExtensionsClientOutputs struct {
	// AppID indicates the FIDO AppID Extension was acted upon.
	AppID *bool `json:"appid,omitempty"`

	// AppIDExclude indicates the FIDO AppID Exclusion Extension was acted upon.
	AppIDExclude *bool `json:"appidExclude,omitempty"`

	// CredProps reports the properties of a newly created credential.
	CredProps *CredentialPropertiesOutput `json:"credProps,omitempty"`

	// PRF reports the availability and results of the pseudo-random function extension.
	PRF *PRFOutputs `json:"prf,omitempty"`

	// LargeBlob reports large blob support at registration, or the read or written blob at authentication.
	LargeBlob *LargeBlobOutputs `json:"largeBlob,omitempty"`

	// RemoteClientDataJSON indicates the Remote Client Data JSON Extension was acted upon, which means the local
	// client delegated every Relying Party ID and origin check to a remote host. See
	// [ExtensionRemoteClientDataJSON], which records that this extension is not yet ratified.
	RemoteClientDataJSON *bool `json:"remoteClientDataJSON,omitempty"`

	// HMACCreateSecret indicates the CTAP hmac-secret was provisioned at registration.
	HMACCreateSecret *bool `json:"hmacCreateSecret,omitempty"`

	// HMACGetSecret reports the CTAP hmac-secret evaluation results.
	HMACGetSecret *HMACGetSecretOutputs `json:"hmacGetSecret,omitempty"`

	// Extra carries extension outputs this library does not model.
	Extra map[string]any `json:"-"`

	// nullModelled lists the modelled extension identifiers the client returned with a JSON null value. A null
	// leaves the typed field nil, but the member was still present in the response, and
	// [AuthenticationExtensionsClientOutputs.Verify] must be able to see it: without this an unsolicited modelled
	// output could evade the unsolicited check simply by being null, while an unsolicited unmodelled one could not,
	// because a null value in [AuthenticationExtensionsClientOutputs.Extra] is still a key.
	//
	// It is decoder state rather than part of the IDL, hence unexported, and is therefore not reproduced by
	// [AuthenticationExtensionsClientOutputs.MarshalJSON]; a null member does not survive a marshal round trip.
	nullModelled []string
}

// CredentialPropertiesOutput represents the CredentialPropertiesOutput IDL. The editor's draft defines no member
// other than rk.
//
// Specification: §10.1.3. Credential Properties Extension (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-credential-properties-extension)
type CredentialPropertiesOutput struct {
	// RK reports whether the created credential is a client-side discoverable credential. A false value is
	// meaningful and distinct from the client not reporting the property at all.
	RK *bool `json:"rk,omitempty"`
}

// PRFOutputs represents the AuthenticationExtensionsPRFOutputsJSON IDL.
//
// Specification: §10.1.4. Pseudo-random function extension (https://www.w3.org/TR/webauthn-3/#prf-extension)
type PRFOutputs struct {
	// Enabled reports whether the pseudo-random function is available for the credential. It is the answer to the
	// bare "prf":{} input a Relying Party sends at registration. A false value is meaningful and distinct from
	// the client not reporting availability at all.
	Enabled *bool `json:"enabled,omitempty"`

	// Results carries the outputs of evaluating the pseudo-random function over the requested salts. Second is
	// only set when a second salt was supplied.
	Results *PRFValues `json:"results,omitempty"`
}

// LargeBlobOutputs represents the AuthenticationExtensionsLargeBlobOutputsJSON IDL.
//
// Specification: §10.1.5. Large blob storage extension (https://www.w3.org/TR/webauthn-3/#sctn-large-blob-extension)
type LargeBlobOutputs struct {
	// Supported reports whether the created credential supports large blob storage. It is only present at
	// registration, in answer to the 'support' input. A false value is meaningful and distinct from the client
	// not reporting support at all; [AuthenticationExtensionsClientOutputs.Verify] rejects both when support was
	// requested as required.
	Supported *bool `json:"supported,omitempty"`

	// Blob is the stored blob, present at authentication in answer to a 'read' input.
	Blob URLEncodedBase64 `json:"blob,omitempty"`

	// Written reports whether the blob supplied by a 'write' input was stored. A false value is meaningful and
	// distinct from the client not reporting the outcome at all.
	Written *bool `json:"written,omitempty"`
}

// HMACGetSecretOutputs represents the outputs of the CTAP hmac-secret extension during authentication.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
type HMACGetSecretOutputs struct {
	// Output1 is the HMAC secret evaluated over the first salt.
	Output1 URLEncodedBase64 `json:"output1,omitempty"`

	// Output2 is the HMAC secret evaluated over the second salt, present only when a second salt was supplied.
	Output2 URLEncodedBase64 `json:"output2,omitempty"`
}

// extensionOutputNames lists the identifiers of every modelled extension output in the order they are reported by
// [AuthenticationExtensionsClientOutputs.Present]. Extra keys follow, sorted.
var extensionOutputNames = []string{
	ExtensionAppID,
	ExtensionAppIDExclude,
	ExtensionCredProps,
	ExtensionPRF,
	ExtensionLargeBlob,
	ExtensionRemoteClientDataJSON,
	ExtensionHMACCreateSecret,
	ExtensionHMACGetSecret,
}

// MarshalJSON implements the [json.Marshaler] interface, merging
// [AuthenticationExtensionsClientOutputs.Extra] into the top-level object.
func (o AuthenticationExtensionsClientOutputs) MarshalJSON() (data []byte, err error) {
	type alias AuthenticationExtensionsClientOutputs

	if data, err = json.Marshal(alias(o)); err != nil {
		return nil, err
	}

	return extensionsMarshalExtra(data, extensionOutputNames, o.Extra, "extension outputs")
}

// UnmarshalJSON implements the [json.Unmarshaler] interface, collecting unrecognised members into
// [AuthenticationExtensionsClientOutputs.Extra].
func (o *AuthenticationExtensionsClientOutputs) UnmarshalJSON(data []byte) (err error) {
	type alias AuthenticationExtensionsClientOutputs

	var decoded alias

	if err = json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	var members map[string]json.RawMessage

	if err = json.Unmarshal(data, &members); err != nil {
		return err
	}

	// Deleting by case-insensitive match (rather than deleting each exact name in extensionOutputNames) matters
	// because the alias decode above already bound a case-variant key (e.g. "AppID") to its modelled field via
	// encoding/json's case-insensitive fallback. Deleting only the exact-case name would leave that key in members
	// and duplicate it into Extra alongside the typed field it was actually bound to.
	//
	// A modelled member whose value is null leaves the typed field nil, so it is recorded under its canonical
	// identifier before being deleted; see the nullModelled documentation.
	for key, value := range members {
		name, modelled := extensionNameCanonical(extensionOutputNames, key)
		if !modelled {
			continue
		}

		if bytes.Equal(bytes.TrimSpace(value), jsonNull) {
			decoded.nullModelled = append(decoded.nullModelled, name)
		}

		delete(members, key)
	}

	// The map iteration order above is undefined, so the identifiers are sorted to keep Present deterministic.
	slices.Sort(decoded.nullModelled)

	if len(members) != 0 {
		decoded.Extra = make(map[string]any, len(members))

		for key, value := range members {
			var decodedValue any

			if err = json.Unmarshal(value, &decodedValue); err != nil {
				return fmt.Errorf("error unmarshalling extension outputs: extra extension %q: %w", key, err)
			}

			decoded.Extra[key] = decodedValue
		}
	}

	*o = AuthenticationExtensionsClientOutputs(decoded)

	return nil
}

// IsZero returns true when no extension output is set. It is used by the encoding/json omitzero tag option so a
// [ParsedPublicKeyCredential] or [PublicKeyCredential] whose client reported no extension output does not marshal
// an empty clientExtensionResults member.
//
// It is defined in terms of [AuthenticationExtensionsClientOutputs.Present] so the two cannot disagree about what
// "set" means.
func (o AuthenticationExtensionsClientOutputs) IsZero() bool {
	return len(o.Present()) == 0
}

// Present returns the extension identifiers present in these outputs, in specification order followed by the
// sorted [AuthenticationExtensionsClientOutputs.Extra] keys.
//
// A modelled member the client returned as JSON null is present: it leaves the typed field nil, but the client did
// return the member, and the unsolicited output check must treat it the same as the unmodelled null it would
// otherwise be inconsistent with.
func (o AuthenticationExtensionsClientOutputs) Present() (names []string) {
	for _, present := range []struct {
		name string
		set  bool
	}{
		{ExtensionAppID, o.AppID != nil},
		{ExtensionAppIDExclude, o.AppIDExclude != nil},
		{ExtensionCredProps, o.CredProps != nil},
		{ExtensionPRF, o.PRF != nil},
		{ExtensionLargeBlob, o.LargeBlob != nil},
		{ExtensionRemoteClientDataJSON, o.RemoteClientDataJSON != nil},
		{ExtensionHMACCreateSecret, o.HMACCreateSecret != nil},
		{ExtensionHMACGetSecret, o.HMACGetSecret != nil},
	} {
		if present.set || slices.Contains(o.nullModelled, present.name) {
			names = append(names, present.name)
		}
	}

	return append(names, slices.Sorted(maps.Keys(o.Extra))...)
}

// Map returns the outputs in their untyped map form, equivalent to the marshalled JSON object.
func (o AuthenticationExtensionsClientOutputs) Map() (out map[string]any, err error) {
	var data []byte

	if data, err = json.Marshal(o); err != nil {
		return nil, err
	}

	out = map[string]any{}

	if err = json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}
