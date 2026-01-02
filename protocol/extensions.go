package protocol

import "encoding/json"

// Extensions are discussed in §9. WebAuthn Extensions (https://www.w3.org/TR/webauthn/#extensions).

// For a list of commonly supported extensions, see §10. Defined Extensions
// (https://www.w3.org/TR/webauthn/#sctn-defined-extensions).

type AuthenticationExtensionsClientOutputs map[string]any

const (
	ExtensionAppID        = "appid"
	ExtensionAppIDExclude = "appidExclude"
)

func NewExtensionsClientInput[C ExtensionsClientInputContents](contents C) (input *ExtensionsClientInput, err error) {
	return &ExtensionsClientInput{
		contents: contents,
	}, nil
}

type Marshallable interface {
	json.Marshaler
	json.Unmarshaler
}

type ExtensionsClientInputContents interface {
	Marshallable

	*AssertionExtensionsClientInputs | *AttestationExtensionsClientInputs
}

type ExtensionsClientInput struct {
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
