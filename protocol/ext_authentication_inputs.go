package protocol

import (
	"encoding/json"
)

type AssertionExtensionsClientInputs struct {
	AppID             *string             `json:"appid,omitempty"`
	GetCredBlob       *bool               `json:"getCredBlob,omitempty"`
	HMACGetSecret     *HMACGetSecretInput `json:"hmacGetSecret,omitempty"`
	LargeBlob         *LargeBlobInputs    `json:"largeBlob,omitempty"`
	LargeBlobKey      *bool               `json:"largeBlobKey,omitempty"`
	PRF               *PRFInputs          `json:"prf,omitempty"`
	ThirdPartyPayment *bool               `json:"thirdPartyPayment,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (a *AssertionExtensionsClientInputs) UnmarshalJSON(data []byte) (err error) {
	type alias AssertionExtensionsClientInputs

	var known alias

	if err = json.Unmarshal(data, &known); err != nil {
		return err
	}

	*a = AssertionExtensionsClientInputs(known)

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
	delete(m, "thirdPartyPayment")

	if len(m) > 0 {
		a.Extra = m
	}

	return nil
}

func (a AssertionExtensionsClientInputs) MarshalJSON() (data []byte, err error) {
	type alias AssertionExtensionsClientInputs

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

type HMACGetSecretInput struct {
	Salt1 URLEncodedBase64  `json:"salt1"`
	Salt2 *URLEncodedBase64 `json:"salt2,omitempty"`
}

var (
	_ json.Marshaler   = (*AssertionExtensionsClientInputs)(nil)
	_ json.Unmarshaler = (*AssertionExtensionsClientInputs)(nil)
	_ Marshallable     = (*AssertionExtensionsClientInputs)(nil)
	_ json.Marshaler   = AssertionExtensionsClientInputs{}
)
