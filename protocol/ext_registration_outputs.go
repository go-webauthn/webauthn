package protocol

import "encoding/json"

type RegistrationExtensionsClientOutputs struct {
	AppIDExclude     *bool                                   `json:"appidExclude,omitempty"`
	CredBlob         *bool                                   `json:"credBlob,omitempty"`
	CredProps        *CredentialPropertiesOutput             `json:"credProps,omitempty"`
	CredProtect      any                                     `json:"credProtect,omitempty"`
	HMACCreateSecret *bool                                   `json:"hmacCreateSecret,omitempty"`
	LargeBlob        *RegistrationExtensionsLargeBlobOutputs `json:"largeBlob,omitempty"`
	MinPinLength     *uint                                   `json:"minPinLength,omitempty"`
	PRF              *RegistrationExtensionsPRFOutputs       `json:"prf,omitempty"`

	Raw json.RawMessage `json:"-"`
}

func (r *RegistrationExtensionsClientOutputs) UnmarshalJSON(data []byte) (err error) {
	r.Raw = append(r.Raw, data...)

	type Alias RegistrationExtensionsClientOutputs

	aux := &struct{ *Alias }{Alias: (*Alias)(r)}

	return json.Unmarshal(data, aux)
}

func (r RegistrationExtensionsClientOutputs) MarshalJSON() (data []byte, err error) {
	type Alias RegistrationExtensionsClientOutputs

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

type RegistrationExtensionsLargeBlobOutputs struct {
	Supported *bool `json:"supported,omitempty"`
}

type RegistrationExtensionsPRFOutputs struct {
	Enabled *bool                              `json:"enabled,omitempty"`
	Results *AuthenticationExtensionsPRFValues `json:"results,omitempty"`
}

type CredentialPropertiesOutput struct {
	ResidentKey *bool `json:"rk,omitempty"`
}

var (
	_ json.Marshaler   = (*RegistrationExtensionsClientOutputs)(nil)
	_ json.Unmarshaler = (*RegistrationExtensionsClientOutputs)(nil)
	_ Marshallable     = (*RegistrationExtensionsClientOutputs)(nil)
	_ json.Marshaler   = RegistrationExtensionsClientOutputs{}
)