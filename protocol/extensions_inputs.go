package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"slices"
)

// AuthenticationExtensions represents the AuthenticationExtensionsClientInputs IDL. It contains additional
// parameters requesting additional processing by the client and authenticator.
//
// Members are marshalled in the AuthenticationExtensionsClientInputsJSON form, i.e. buffer sources are base64url
// encoded strings, which is the form consumed by PublicKeyCredential.parseCreationOptionsFromJSON().
//
// A JSON member whose key matches a modelled name only by case (e.g. "CredProps" for "credProps") is bound to that
// modelled field, not collected into [AuthenticationExtensions.Extra]: encoding/json resolves the case-insensitive
// match during the first decoding pass, before UnmarshalJSON ever sees the untyped member map. If such a member's
// value has the wrong type for the modelled field, unmarshalling fails outright rather than falling back to Extra.
// encoding/json (v1, the only version this module may use) offers no way to defer that binding.
//
// Specification: §5.7.1. Authentication Extensions Client Inputs (https://www.w3.org/TR/webauthn-3/#iface-authentication-extensions-client-inputs)
//
// Specification: §10.1. Client Extensions (https://www.w3.org/TR/webauthn-3/#sctn-defined-client-extensions)
type AuthenticationExtensions struct {
	// AppID is the FIDO AppID Extension input. Authentication only.
	AppID string `json:"appid,omitempty"`

	// AppIDExclude is the FIDO AppID Exclusion Extension input. Registration only.
	AppIDExclude string `json:"appidExclude,omitempty"`

	// CredProps requests the Credential Properties Extension. Registration only.
	CredProps bool `json:"credProps,omitempty"`

	// PRF is the Pseudo-random function Extension input. It is a pointer because an empty dictionary is a
	// meaningful input for this extension and only this extension: a Relying Party sends "prf":{} at registration
	// to ask whether the pseudo-random function is available for the credential being created, and the client
	// answers with the 'enabled' output. A value type combined with omitzero cannot express the difference between
	// an absent member and a member present but empty, so a non-nil pointer to a zero value is what carries the
	// bare availability probe.
	PRF *PRFInputs `json:"prf,omitempty"`

	// LargeBlob is the Large blob storage Extension input.
	LargeBlob LargeBlobInputs `json:"largeBlob,omitzero"`

	// RemoteClientDataJSON is the Remote Client Data JSON Extension input. This member is set by a remote desktop
	// web client and a Relying Party should not normally set it. See [ExtensionRemoteClientDataJSON], which records
	// that this extension is not yet ratified.
	RemoteClientDataJSON string `json:"remoteClientDataJSON,omitempty"`

	// CredentialProtectionPolicy is the CTAP credProtect policy. Registration only.
	CredentialProtectionPolicy CredentialProtectionPolicy `json:"credentialProtectionPolicy,omitempty"`

	// EnforceCredentialProtectionPolicy requires the credProtect policy is honoured. Registration only.
	EnforceCredentialProtectionPolicy bool `json:"enforceCredentialProtectionPolicy,omitempty"`

	// MinPinLength requests the authenticator minimum PIN length. Registration only.
	MinPinLength bool `json:"minPinLength,omitempty"`

	// CredBlob is the blob to store with the credential. Registration only.
	CredBlob URLEncodedBase64 `json:"credBlob,omitempty"`

	// GetCredBlob requests the blob stored with the credential. Authentication only.
	GetCredBlob bool `json:"getCredBlob,omitempty"`

	// HMACCreateSecret requests provisioning of the CTAP hmac-secret. Registration only.
	HMACCreateSecret bool `json:"hmacCreateSecret,omitempty"`

	// HMACGetSecret requests evaluation of the CTAP hmac-secret. Authentication only.
	HMACGetSecret HMACGetSecretInputs `json:"hmacGetSecret,omitzero"`

	// UVM requests the user verification methods used for the operation.
	UVM bool `json:"uvm,omitempty"`

	// Extra carries extension inputs this library does not model. Entries are merged into the top-level object
	// when marshalling and unrecognised members are collected here when unmarshalling. An entry whose key matches
	// a modelled extension is an error, as the intent would be ambiguous.
	Extra map[string]any `json:"-"`
}

// extensionInputNames lists the identifiers of every modelled extension input in the order they are reported by
// [AuthenticationExtensions.Requested]. Extra keys follow, sorted.
var extensionInputNames = []string{
	ExtensionAppID,
	ExtensionAppIDExclude,
	ExtensionCredProps,
	ExtensionPRF,
	ExtensionLargeBlob,
	ExtensionRemoteClientDataJSON,
	ExtensionCredentialProtectionPolicy,
	ExtensionEnforceCredentialProtectionPolicy,
	ExtensionMinPinLength,
	ExtensionCredBlob,
	ExtensionGetCredBlob,
	ExtensionHMACCreateSecret,
	ExtensionHMACGetSecret,
	ExtensionUVM,
}

// MarshalJSON implements the [json.Marshaler] interface, merging [AuthenticationExtensions.Extra] into the
// top-level object. Marshalling always routes through a map so the key ordering does not depend on whether Extra
// is populated.
func (e AuthenticationExtensions) MarshalJSON() (data []byte, err error) {
	type alias AuthenticationExtensions

	if data, err = json.Marshal(alias(e)); err != nil {
		return nil, err
	}

	return extensionsMarshalExtra(data, extensionInputNames, e.Extra, "extension inputs")
}

// UnmarshalJSON implements the [json.Unmarshaler] interface, collecting unrecognised members into
// [AuthenticationExtensions.Extra].
func (e *AuthenticationExtensions) UnmarshalJSON(data []byte) (err error) {
	type alias AuthenticationExtensions

	var decoded alias

	if err = json.Unmarshal(data, &decoded); err != nil {
		return err
	}

	var members map[string]json.RawMessage

	if err = json.Unmarshal(data, &members); err != nil {
		return err
	}

	// Deleting by case-insensitive match (rather than deleting each exact name in extensionInputNames) matters
	// because the alias decode above already bound a case-variant key (e.g. "CredProps") to its modelled field via
	// encoding/json's case-insensitive fallback. Deleting only the exact-case name would leave that key in members
	// and duplicate it into Extra alongside the typed field it was actually bound to.
	for key := range members {
		if extensionNameModelled(extensionInputNames, key) {
			delete(members, key)
		}
	}

	if len(members) != 0 {
		decoded.Extra = make(map[string]any, len(members))

		for key, value := range members {
			var decodedValue any

			if err = json.Unmarshal(value, &decodedValue); err != nil {
				return fmt.Errorf("error unmarshalling extension inputs: extra extension %q: %w", key, err)
			}

			decoded.Extra[key] = decodedValue
		}
	}

	*e = AuthenticationExtensions(decoded)

	return nil
}

// IsZero returns true when no extension input is set. It is used by the encoding/json omitzero tag option so a
// Relying Party that requests no extensions does not send an empty extensions member to the client.
//
// It is defined in terms of [AuthenticationExtensions.Requested] so the two cannot disagree about what "set"
// means. Requested does not allocate for a zero value, so neither does this.
func (e AuthenticationExtensions) IsZero() bool {
	return len(e.Requested()) == 0
}

// Requested returns the extension identifiers present in these inputs, in specification order followed by the
// sorted [AuthenticationExtensions.Extra] keys. It returns nil rather than an empty slice when no extension is
// requested, so the result survives a round trip through an encoding that elides empty collections.
//
// The result is stored in [SessionExtensions] and drives the unsolicited output check performed by
// [AuthenticationExtensionsClientOutputs.Verify].
func (e AuthenticationExtensions) Requested() (names []string) {
	for _, present := range []struct {
		name string
		set  bool
	}{
		{ExtensionAppID, e.AppID != ""},
		{ExtensionAppIDExclude, e.AppIDExclude != ""},
		{ExtensionCredProps, e.CredProps},
		{ExtensionPRF, e.PRF != nil},
		{ExtensionLargeBlob, !e.LargeBlob.IsZero()},
		{ExtensionRemoteClientDataJSON, e.RemoteClientDataJSON != ""},
		{ExtensionCredentialProtectionPolicy, e.CredentialProtectionPolicy != ""},
		{ExtensionEnforceCredentialProtectionPolicy, e.EnforceCredentialProtectionPolicy},
		{ExtensionMinPinLength, e.MinPinLength},
		{ExtensionCredBlob, len(e.CredBlob) != 0},
		{ExtensionGetCredBlob, e.GetCredBlob},
		{ExtensionHMACCreateSecret, e.HMACCreateSecret},
		{ExtensionHMACGetSecret, !e.HMACGetSecret.IsZero()},
		{ExtensionUVM, e.UVM},
	} {
		if present.set {
			names = append(names, present.name)
		}
	}

	return append(names, slices.Sorted(maps.Keys(e.Extra))...)
}

// Map returns the inputs in their untyped map form, equivalent to the marshalled JSON object. It exists so callers
// migrating from the previous map-based representation can adapt existing logging, storage, or conformance code
// incrementally.
func (e AuthenticationExtensions) Map() (out map[string]any, err error) {
	var data []byte

	if data, err = json.Marshal(e); err != nil {
		return nil, err
	}

	out = map[string]any{}

	if err = json.Unmarshal(data, &out); err != nil {
		return nil, err
	}

	return out, nil
}

// ParseAuthenticationExtensions converts a map of extension inputs into typed fields. Recognised identifiers whose
// values have the wrong type return an error and unrecognised identifiers are placed in
// [AuthenticationExtensions.Extra].
//
// This is the only supported ingress for the untyped map form; no functional option accepts a map, so the coercion
// is an explicit and fallible step the caller owns.
func ParseAuthenticationExtensions(in map[string]any) (out AuthenticationExtensions, err error) {
	var data []byte

	if data, err = json.Marshal(in); err != nil {
		return out, fmt.Errorf("error parsing extension inputs: %w", err)
	}

	if err = json.Unmarshal(data, &out); err != nil {
		var typeErr *json.UnmarshalTypeError

		if errors.As(err, &typeErr) {
			return AuthenticationExtensions{}, fmt.Errorf("error parsing extension inputs: extension %q: %w", typeErr.Field, err)
		}

		return AuthenticationExtensions{}, fmt.Errorf("error parsing extension inputs: %w", err)
	}

	return out, nil
}

// Validate reports whether these inputs are internally consistent and applicable to the given ceremony. Every
// problem found is reported, joined with [errors.Join], rather than only the first.
//
// Registration-only members are rejected during authentication and authentication-only members are rejected during
// registration. A ceremony which is neither [CreateCeremony] nor [AssertCeremony] is treated as a registration, so
// an unexpected value fails closed rather than admitting the authentication-only members unchecked.
//
// Members the IDL marks required must also be non-empty when the dictionary containing them is present: the 'first'
// value of a PRF 'eval' and of every 'evalByCredential' entry, and the 'salt1' value of an 'hmacGetSecret'. Without
// these the member would be marshalled as a JSON null.
func (e AuthenticationExtensions) Validate(c CeremonyType) (err error) {
	var errs []error

	// The comparison is against AssertCeremony rather than CreateCeremony so an unrecognised ceremony is treated as
	// a registration, mirroring [AuthenticationExtensionsClientOutputs.Verify]. Treating it as an authentication
	// would instead admit the authentication-only appid, getCredBlob and hmacGetSecret members unchecked.
	creation := c != AssertCeremony

	for _, rule := range []struct {
		name         string
		set          bool
		registration bool
	}{
		{ExtensionAppIDExclude, e.AppIDExclude != "", true},
		{ExtensionCredProps, e.CredProps, true},
		{ExtensionCredentialProtectionPolicy, e.CredentialProtectionPolicy != "", true},
		{ExtensionEnforceCredentialProtectionPolicy, e.EnforceCredentialProtectionPolicy, true},
		{ExtensionMinPinLength, e.MinPinLength, true},
		{ExtensionCredBlob, len(e.CredBlob) != 0, true},
		{ExtensionHMACCreateSecret, e.HMACCreateSecret, true},
		{ExtensionAppID, e.AppID != "", false},
		{ExtensionGetCredBlob, e.GetCredBlob, false},
		{ExtensionHMACGetSecret, !e.HMACGetSecret.IsZero(), false},
	} {
		if !rule.set {
			continue
		}

		if rule.registration && !creation {
			errs = append(errs, fmt.Errorf("extension %q is a registration extension but was provided for an authentication ceremony", rule.name))
		} else if !rule.registration && creation {
			errs = append(errs, fmt.Errorf("extension %q is an authentication extension but was provided for a registration ceremony", rule.name))
		}
	}

	if creation {
		if e.PRF != nil && len(e.PRF.EvalByCredential) != 0 {
			errs = append(errs, fmt.Errorf("extension %q member 'evalByCredential' is an authentication extension member but was provided for a registration ceremony", ExtensionPRF))
		}

		if e.LargeBlob.Read || len(e.LargeBlob.Write) != 0 {
			errs = append(errs, fmt.Errorf("extension %q members 'read' and 'write' are authentication extension members but were provided for a registration ceremony", ExtensionLargeBlob))
		}
	} else if e.LargeBlob.Support != "" {
		errs = append(errs, fmt.Errorf("extension %q member 'support' is a registration extension member but was provided for an authentication ceremony", ExtensionLargeBlob))
	}

	// PRFValues is shared between 'eval' and the entries of 'evalByCredential', so the required 'first' member has
	// to be checked against each use rather than against the type.
	if e.PRF != nil {
		if !e.PRF.Eval.IsZero() && len(e.PRF.Eval.First) == 0 {
			errs = append(errs, fmt.Errorf("extension %q member 'eval' requires a non-empty 'first' value", ExtensionPRF))
		}

		// The keys are sorted so the reported problems do not depend on the map iteration order.
		for _, id := range slices.Sorted(maps.Keys(e.PRF.EvalByCredential)) {
			if len(e.PRF.EvalByCredential[id].First) == 0 {
				errs = append(errs, fmt.Errorf("extension %q member 'evalByCredential' entry %q requires a non-empty 'first' value", ExtensionPRF, id))
			}
		}
	}

	if !e.HMACGetSecret.IsZero() && len(e.HMACGetSecret.Salt1) == 0 {
		errs = append(errs, fmt.Errorf("extension %q member 'salt1' requires a non-empty value", ExtensionHMACGetSecret))
	}

	if len(e.LargeBlob.Write) != 0 && e.LargeBlob.Read {
		errs = append(errs, fmt.Errorf("extension %q members 'read' and 'write' are mutually exclusive", ExtensionLargeBlob))
	}

	return errors.Join(errs...)
}
