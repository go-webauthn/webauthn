package protocol

import "encoding/json"

// Extensions are discussed in §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn/#extensions).

// For a list of commonly supported extensions, see §10. Defined Extensions
// (https://www.w3.org/TR/webauthn/#sctn-defined-extensions).

type AuthenticationExtensionsClientOutputsLegacy map[string]any

const (
	ExtensionAppID        = "appid"
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

type LargeBlobSupport string

const (
	LargeBlobSupportRequired  LargeBlobSupport = "required"
	LargeBlobSupportPreferred LargeBlobSupport = "preferred"
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
