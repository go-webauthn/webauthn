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

	Raw json.RawMessage `json:"-"`
}

func (r *RegistrationExtensionsClientInputs) UnmarshalJSON(data []byte) (err error) {
	r.Raw = append(r.Raw, data...)

	type Alias RegistrationExtensionsClientInputs

	aux := &struct{ *Alias }{Alias: (*Alias)(r)}

	return json.Unmarshal(data, aux)
}

func (r RegistrationExtensionsClientInputs) MarshalJSON() (data []byte, err error) {
	type Alias RegistrationExtensionsClientInputs

	if data, err = json.Marshal(Alias(r)); err != nil {
		return nil, err
	}

	if len(r.Raw) == 0 {
		return data, nil
	}

	var (
		structMap, rawMap map[string]json.RawMessage
	)

	if err = json.Unmarshal(data, &structMap); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(r.Raw, &rawMap); err != nil {
		return nil, err
	}

	merged := rawMap
	for k, v := range structMap {
		merged[k] = v
	}

	return json.Marshal(merged)
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