package protocol

import "encoding/json"

type AttestationExtensionsClientOutputs struct {
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
	ThirdPartyPayment   any               `json:"thirdPartyPayment,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (r *AttestationExtensionsClientOutputs) UnmarshalJSON(data []byte) (err error) {
	type alias AttestationExtensionsClientOutputs

	var known alias

	if err = json.Unmarshal(data, &known); err != nil {
		return err
	}

	*r = AttestationExtensionsClientOutputs(known)

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

func (r AttestationExtensionsClientOutputs) MarshalJSON() (data []byte, err error) {
	type alias AttestationExtensionsClientOutputs

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
	_ json.Marshaler   = (*AttestationExtensionsClientOutputs)(nil)
	_ json.Unmarshaler = (*AttestationExtensionsClientOutputs)(nil)
	_ Marshallable     = (*AttestationExtensionsClientOutputs)(nil)
	_ json.Marshaler   = AttestationExtensionsClientOutputs{}
)
