package protocol

import (
	"encoding/json"
	"errors"
)

// Extensions are discussed in §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn/#extensions).

// For a list of commonly supported extensions, see §10. Defined Extensions
// (https://www.w3.org/TR/webauthn/#sctn-defined-extensions).

// AuthenticationExtensionsClientOutputsLegacy represents the IDL of the same name. It is a map of extension identifier
// strings to their output values, returned by the client after a create() or get() call.
//
// Specification: §5.9. Authentication Extensions Client Outputs (https://www.w3.org/TR/webauthn/#iface-authentication-extensions-client-outputs)
type AuthenticationExtensionsClientOutputsLegacy map[string]any

const (
	// ExtensionAppID is the FIDO AppID Extension identifier. It is used during authentication to allow credentials
	// registered via the legacy FIDO U2F JavaScript API to be used with WebAuthn.
	//
	// Specification: §10.1. FIDO AppID Extension (https://www.w3.org/TR/webauthn/#sctn-appid-extension)
	ExtensionAppID = "appid"

	// ExtensionAppIDExclude is the FIDO AppID Exclusion Extension identifier. It is used during registration to
	// exclude credentials previously registered via the legacy FIDO U2F JavaScript API.
	//
	// Specification: §10.2. FIDO AppID Exclusion Extension (https://www.w3.org/TR/webauthn/#sctn-appid-exclude-extension)
	ExtensionAppIDExclude = "appidExclude"
)

func NewExtensionsClientInputs[C ExtensionsClientInputsContents](contents C) (input *ExtensionsClientInputs, err error) {
	return &ExtensionsClientInputs{
		contents: contents,
	}, nil
}

func NewExtensionsClientOutputs[C ExtensionsClientOutputsContents](contents C) (input *ExtensionsClientOutputs, err error) {
	return &ExtensionsClientOutputs{
		contents: contents,
	}, nil
}

type Marshallable interface {
	json.Marshaler
	json.Unmarshaler
}

type ExtensionsClientInputsContents interface {
	Marshallable

	*AuthenticationExtensionsClientInputs | *RegistrationExtensionsClientInputs
}

type ExtensionsClientOutputsContents interface {
	Marshallable

	*AuthenticationExtensionsClientOutputs | *RegistrationExtensionsClientOutputs
}

type ExtensionsClientInputs struct {
	contents Marshallable
}

type ExtensionsClientOutputs struct {
	contents Marshallable
}

type CredentialProtectionPolicy int

const (
	UserVerificationOptional                     CredentialProtectionPolicy = iota // userVerificationOptional
	UserVerificationOptionalWithCredentialIDList                                   // userVerificationOptionalWithCredentialIDList
	UserVerificationRequired                                                       // userVerificationRequired
)

func (p CredentialProtectionPolicy) String() string {
	switch p {
	case UserVerificationOptional:
		return "userVerificationOptional"
	case UserVerificationOptionalWithCredentialIDList:
		return "userVerificationOptionalWithCredentialIDList"
	case UserVerificationRequired:
		return "userVerificationRequired"
	default:
		return ""
	}
}

func (p CredentialProtectionPolicy) MarshalJSON() ([]byte, error) {
	return json.Marshal(p.String())
}

func (p *CredentialProtectionPolicy) UnmarshalJSON(data []byte) error {
	var v string

	if err := json.Unmarshal(data, &v); err != nil {
		return err
	}

	switch v {
	case UserVerificationOptional.String():
		*p = UserVerificationOptional
	case UserVerificationOptionalWithCredentialIDList.String():
		*p = UserVerificationOptionalWithCredentialIDList
	case UserVerificationRequired.String():
		*p = UserVerificationRequired
	default:
		return errors.New("unknown CredentialProtectionPolicy")
	}

	return nil
}

type LargeBlobSupport int

func (s LargeBlobSupport) MarshalJSON() ([]byte, error) {
	var value string

	switch s {
	case LargeBlobSupportRequired:
		value = "required"
	case LargeBlobSupportPreferred:
		value = "preferred"
	}

	return json.Marshal(value)
}

const (
	LargeBlobSupportRequired LargeBlobSupport = iota
	LargeBlobSupportPreferred
)

type PRFInputs struct {
	Eval             *PRFValues           `json:"eval,omitempty"`
	EvalByCredential map[string]PRFValues `json:"evalByCredential,omitempty"`
}

type PRFOutputs struct {
	Enabled *bool      `json:"enabled,omitempty"`
	Results *PRFValues `json:"results,omitempty"`
}

type PRFValues struct {
	First  URLEncodedBase64  `json:"first"`
	Second *URLEncodedBase64 `json:"second,omitempty"`
}

type LargeBlobInputs struct {
	Support *LargeBlobSupport `json:"support,omitempty"`
	Read    *bool             `json:"read,omitempty"`
	Write   *URLEncodedBase64 `json:"write,omitempty"`
}

type LargeBlobOutputs struct {
	Supported *bool             `json:"supported,omitempty"`
	Blob      *URLEncodedBase64 `json:"blob,omitempty"`
	Written   *bool             `json:"written,omitempty"`
}

type CredPropsOutputs struct {
	ResidentKey *bool `json:"rk,omitempty"`
}
