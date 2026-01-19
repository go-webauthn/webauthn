package protocol

import (
	"encoding/json"
	"errors"
)

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

type AuthenticationExtensionsPRFInputs struct {
	Eval             *AuthenticationExtensionsPRFValues           `json:"eval,omitempty"`
	EvalByCredential map[string]AuthenticationExtensionsPRFValues `json:"evalByCredential,omitempty"`
}

type AuthenticationExtensionsPRFValues struct {
	First  URLEncodedBase64  `json:"first"`
	Second *URLEncodedBase64 `json:"second,omitempty"`
}
