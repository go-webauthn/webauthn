package protocol

import "encoding/json"

type RegistrationExtensionsClientInputs struct {
	AppIDExclude      *string                                  `json:"appidExclude,omitempty"`
	CredBlob          *URLEncodedBase64                        `json:"credBlob,omitempty"`
	CredProps         *bool                                    `json:"credProps,omitempty"`
	CredProtect       *RegistrationExtensionsCredProtectInputs `json:"credProtect,omitempty"`
	HMACCreateSecret  *bool                                    `json:"hmacCreateSecret,omitempty"`
	LargeBlob         *RegistrationExtensionsLargeBlobInputs   `json:"largeBlob,omitempty"`
	MinPinLength      *bool                                    `json:"minPinLength,omitempty"`
	PRF               *AuthenticationExtensionsPRFInputs       `json:"prf,omitempty"`
	ThirdPartyPayment *bool                                    `json:"thirdPartyPayment,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (r *RegistrationExtensionsClientInputs) UnmarshalJSON(data []byte) (err error) {
	type alias RegistrationExtensionsClientInputs

	var known alias

	if err = json.Unmarshal(data, &known); err != nil {
		return err
	}

	*r = RegistrationExtensionsClientInputs(known)

	var m map[string]json.RawMessage

	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}

	delete(m, "appidExclude")
	delete(m, "credBlob")
	delete(m, "credProps")
	delete(m, "credProtect")
	delete(m, "hmacCreateSecret")
	delete(m, "largeBlob")
	delete(m, "minPinLength")
	delete(m, "prf")
	delete(m, "thirdPartyPayment")

	if len(m) > 0 {
		r.Extra = m
	}

	return nil
}

func (r RegistrationExtensionsClientInputs) MarshalJSON() (data []byte, err error) {
	type alias RegistrationExtensionsClientInputs

	m := map[string]any{}

	if data, err = json.Marshal(alias(r)); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	for k, v := range r.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}

	return json.Marshal(m)
}

type RegistrationExtensionsCredProtectInputs struct {
	CredentialProtectionPolicy        *CredentialProtectionPolicy `json:"credentialProtectionPolicy,omitempty"`
	EnforceCredentialProtectionPolicy *bool                       `json:"enforceCredentialProtectionPolicy,omitempty"`
}

type RegistrationExtensionsLargeBlobInputs struct {
	Support *LargeBlobSupport `json:"support,omitempty"`
}

var (
	_ json.Marshaler   = (*RegistrationExtensionsClientInputs)(nil)
	_ json.Unmarshaler = (*RegistrationExtensionsClientInputs)(nil)
	_ Marshallable     = (*RegistrationExtensionsClientInputs)(nil)
	_ json.Marshaler   = RegistrationExtensionsClientInputs{}
)
