package protocol

import "encoding/json"

type RegistrationExtensionsClientOutputs struct {
	AppIDExclude        *bool             `json:"appidExclude,omitempty"`
	CredBlob            *bool             `json:"credBlob,omitempty"`
	CredProps           *CredPropsOutputs `json:"credProps,omitempty"`
	CredProtect         any               `json:"credProtect,omitempty"`
	HMACCreateSecret    *bool             `json:"hmacCreateSecret,omitempty"`
	HMACSecretMC        any               `json:"hmac-secret-mc,omitempty"`
	LargeBlob           *LargeBlobOutputs `json:"largeBlob,omitempty"`
	LargeBlobKey        *URLEncodedBase64 `json:"largeBlobKey,omitempty"`
	MinPinLength        *uint             `json:"minPinLength,omitempty"`
	PinComplexityPolicy *bool             `json:"pinComplexityPolicy,omitempty"`
	PRF                 *PRFOutputs       `json:"prf,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (r *RegistrationExtensionsClientOutputs) UnmarshalJSON(data []byte) (err error) {
	type alias RegistrationExtensionsClientOutputs

	var known alias

	if err = json.Unmarshal(data, &known); err != nil {
		return err
	}

	*r = RegistrationExtensionsClientOutputs(known)

	var m map[string]json.RawMessage

	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}

	delete(m, "appidExclude")
	delete(m, "credBlob")
	delete(m, "credProps")
	delete(m, "credProtect")
	delete(m, "hmacCreateSecret")
	delete(m, "hmac-secret-mc")
	delete(m, "largeBlob")
	delete(m, "largeBlobKey")
	delete(m, "minPinLength")
	delete(m, "pinComplexityPolicy")
	delete(m, "prf")
	delete(m, "thirdPartyPayment")

	if len(m) > 0 {
		r.Extra = m
	}

	return nil
}

func (r RegistrationExtensionsClientOutputs) MarshalJSON() (data []byte, err error) {
	type alias RegistrationExtensionsClientOutputs

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

var (
	_ json.Marshaler   = (*RegistrationExtensionsClientOutputs)(nil)
	_ json.Unmarshaler = (*RegistrationExtensionsClientOutputs)(nil)
	_ Marshallable     = (*RegistrationExtensionsClientOutputs)(nil)
	_ json.Marshaler   = RegistrationExtensionsClientOutputs{}
)
