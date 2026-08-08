package protocol

import (
	"math"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// AuthenticatorExtensionOutputs is the decoded form of the extension outputs carried in the authenticator data.
// WebAuthn Level 3 defines no authenticator extensions; every member below is defined by CTAP 2.1 or CTAP 2.2 and
// registered in the IANA "WebAuthn Extension Identifiers" registry.
//
// Specification: §6.1. Authenticator Data (https://www.w3.org/TR/webauthn-3/#sctn-authenticator-data)
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
type AuthenticatorExtensionOutputs struct {
	// CredProtect is the credential protection policy applied to the credential. Registration only.
	CredProtect *CredentialProtectionPolicy `json:"credProtect,omitempty"`

	// MinPinLength is the authenticator's current minimum PIN length. Registration only.
	MinPinLength *uint `json:"minPinLength,omitempty"`

	// CredBlobSet reports whether the requested blob was stored. Registration only.
	CredBlobSet *bool `json:"-"`

	// CredBlob is the blob stored with the credential. Authentication only.
	CredBlob []byte `json:"credBlob,omitempty"`

	// HMACSecret reports whether the hmac-secret was provisioned. Registration only.
	HMACSecret *bool `json:"-"`

	// HMACSecretV is the encrypted hmac-secret output. Authentication only.
	HMACSecretV []byte `json:"-"`

	// UVM reports the user verification methods used for the operation.
	UVM []UserVerificationMethod `json:"uvm,omitempty"`

	// Extra carries authenticator extension outputs this library does not model, and the values of modelled
	// extensions that arrived with an unexpected type.
	Extra map[string]any `json:"-"`
}

// UserVerificationMethod is a single entry of the CTAP uvm extension output.
//
// Registry: https://www.iana.org/assignments/webauthn/webauthn.xhtml
type UserVerificationMethod struct {
	UserVerificationMethod uint32 `json:"userVerificationMethod"`
	KeyProtectionType      uint32 `json:"keyProtectionType"`
	MatcherProtectionType  uint32 `json:"matcherProtectionType"`
}

// credentialProtectionPolicies maps the CTAP credProtect integer values to their policy names.
var credentialProtectionPolicies = map[uint64]CredentialProtectionPolicy{
	1: CredentialProtectionPolicyUserVerificationOptional,
	2: CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList,
	3: CredentialProtectionPolicyUserVerificationRequired,
}

// ParseAuthenticatorExtensionOutputs decodes the CBOR extension outputs from the authenticator data.
//
// A structurally invalid encoding is an error, as the data is signed and malformation indicates something is
// genuinely wrong. A recognised identifier carrying an unexpected type is preserved in
// [AuthenticatorExtensionOutputs.Extra] without an error, so a single non-conforming authenticator cannot fail
// every ceremony it participates in.
func ParseAuthenticatorExtensionOutputs(data []byte) (out *AuthenticatorExtensionOutputs, err error) {
	var members map[string]any

	if err = webauthncbor.Unmarshal(data, &members); err != nil {
		return nil, ErrBadRequest.
			WithDetails("Error decoding authenticator extension outputs").
			WithInfo(err.Error()).
			WithError(err)
	}

	out = &AuthenticatorExtensionOutputs{}

	for key, value := range members {
		if out.assign(key, value) {
			continue
		}

		if out.Extra == nil {
			out.Extra = map[string]any{}
		}

		out.Extra[key] = value
	}

	return out, nil
}

// assign stores a single decoded extension output, reporting whether the identifier was recognised and the value
// had the expected type. A false result sends the entry to Extra.
func (o *AuthenticatorExtensionOutputs) assign(key string, value any) bool {
	switch key {
	case ExtensionCredentialProtectionPolicy, "credProtect":
		raw, ok := value.(uint64)
		if !ok {
			return false
		}

		policy, ok := credentialProtectionPolicies[raw]
		if !ok {
			return false
		}

		o.CredProtect = &policy

		return true
	case ExtensionMinPinLength:
		raw, ok := value.(uint64)
		if !ok {
			return false
		}

		if raw > math.MaxUint {
			return false
		}

		o.MinPinLength = ptr(uint(raw))

		return true
	case ExtensionCredBlob:
		switch raw := value.(type) {
		case bool:
			o.CredBlobSet = ptr(raw)
		case []byte:
			o.CredBlob = raw
		default:
			return false
		}

		return true
	case ExtensionHMACSecret:
		switch raw := value.(type) {
		case bool:
			o.HMACSecret = ptr(raw)
		case []byte:
			o.HMACSecretV = raw
		default:
			return false
		}

		return true
	case ExtensionUVM:
		entries, ok := value.([]any)
		if !ok {
			return false
		}

		methods := make([]UserVerificationMethod, 0, len(entries))

		for _, entry := range entries {
			fields, ok := entry.([]any)
			if !ok || len(fields) != 3 {
				return false
			}

			var method UserVerificationMethod

			for i, field := range fields {
				raw, ok := field.(uint64)
				if !ok {
					return false
				}

				if raw > math.MaxUint32 {
					return false
				}

				switch i {
				case 0:
					method.UserVerificationMethod = uint32(raw)
				case 1:
					method.KeyProtectionType = uint32(raw)
				case 2:
					method.MatcherProtectionType = uint32(raw)
				}
			}

			methods = append(methods, method)
		}

		o.UVM = methods

		return true
	default:
		return false
	}
}
