package protocol

import (
	"encoding/json"
)

type AuthenticationExtensionsClientInputs struct {
	AppID             *string             `json:"appid,omitempty"`
	GetCredBlob       *bool               `json:"getCredBlob,omitempty"`
	HMACGetSecret     *HMACGetSecretInput `json:"hmacGetSecret,omitempty"`
	LargeBlob         *LargeBlobInputs    `json:"largeBlob,omitempty"`
	PRF               *PRFInputs          `json:"prf,omitempty"`
	ThirdPartyPayment *bool               `json:"thirdPartyPayment,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (a *AuthenticationExtensionsClientInputs) UnmarshalJSON(data []byte) (err error) {
	type alias AuthenticationExtensionsClientInputs

	var known alias

	if err = json.Unmarshal(data, &known); err != nil {
		return err
	}

	*a = AuthenticationExtensionsClientInputs(known)

	var m map[string]json.RawMessage

	if err = json.Unmarshal(data, &m); err != nil {
		return err
	}

	delete(m, "appid")
	delete(m, "getCredBlob")
	delete(m, "hmacGetSecret")
	delete(m, "largeBlob")
	delete(m, "prf")
	delete(m, "thirdPartyPayment")

	if len(m) > 0 {
		a.Extra = m
	}

	return nil
}

func (a AuthenticationExtensionsClientInputs) MarshalJSON() (data []byte, err error) {
	type alias AuthenticationExtensionsClientInputs

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
	_ json.Marshaler   = (*AuthenticationExtensionsClientInputs)(nil)
	_ json.Unmarshaler = (*AuthenticationExtensionsClientInputs)(nil)
	_ Marshallable     = (*AuthenticationExtensionsClientInputs)(nil)
	_ json.Marshaler   = AuthenticationExtensionsClientInputs{}
)
