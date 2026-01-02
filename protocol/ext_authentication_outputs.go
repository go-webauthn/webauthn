package protocol

import "encoding/json"

type AssertionExtensionsClienOutputs struct {
	AppID             *bool                 `json:"appid,omitempty"`
	GetCredBlob       *URLEncodedBase64     `json:"getCredBlob,omitempty"`
	HMACGetSecret     *HMACGetSecretOutputs `json:"hmacGetSecret,omitempty"`
	LargeBlob         *LargeBlobOutputs     `json:"largeBlob,omitempty"`
	LargeBlobKey      *URLEncodedBase64     `json:"largeBlobKey,omitempty"`
	PRF               *PRFOutputs           `json:"prf,omitempty"`
	ThirdPartyPayment any                   `json:"thirdPartyPayment,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (a *AssertionExtensionsClienOutputs) UnmarshalJSON(data []byte) (err error) {
	type alias AssertionExtensionsClienOutputs

	var known alias

	if err = json.Unmarshal(data, &known); err != nil {
		return err
	}

	*a = AssertionExtensionsClienOutputs(known)

	var m map[string]json.RawMessage

	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}

	delete(m, "appid")
	delete(m, "getCredBlob")
	delete(m, "hmacGetSecret")
	delete(m, "largeBlob")
	delete(m, "largeBlobKey")
	delete(m, "prf")
	delete(m, "prf")
	delete(m, "thirdPartyPayment")

	if len(m) > 0 {
		a.Extra = m
	}

	return nil
}

func (a AssertionExtensionsClienOutputs) MarshalJSON() (data []byte, err error) {
	type alias AssertionExtensionsClienOutputs

	m := map[string]any{}

	if data, err = json.Marshal(alias(a)); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(data, &m); err != nil {
		return nil, err
	}

	for k, v := range a.Extra {
		if _, exists := m[k]; !exists {
			m[k] = v
		}
	}

	return json.Marshal(m)
}

type HMACGetSecretOutputs struct {
	Output1 URLEncodedBase64  `json:"output1"`
	Output2 *URLEncodedBase64 `json:"output2,omitempty"`
}

var (
	_ json.Marshaler   = (*AssertionExtensionsClienOutputs)(nil)
	_ json.Unmarshaler = (*AssertionExtensionsClienOutputs)(nil)
	_ Marshallable     = (*AssertionExtensionsClienOutputs)(nil)
	_ json.Marshaler   = AssertionExtensionsClienOutputs{}
)
