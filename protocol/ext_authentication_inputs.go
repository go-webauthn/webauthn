package protocol

import (
	"encoding/json"
)

type AuthenticationExtensionsClientInputs struct {
	AppID             *string                                  `json:"appid,omitempty"`
	GetCredBlob       *bool                                    `json:"getCredBlob,omitempty"`
	HMACGetSecret     *HMACGetSecretInput                      `json:"hmacGetSecret,omitempty"`
	LargeBlob         *AuthenticationExtensionsLargeBlobInputs `json:"largeBlob,omitempty"`
	PRF               *AuthenticationExtensionsPRFInputs       `json:"prf,omitempty"`
	ThirdPartyPayment *bool                                    `json:"thirdPartyPayment,omitempty"`

	Raw json.RawMessage `json:"-"`
}

func (a *AuthenticationExtensionsClientInputs) UnmarshalJSON(data []byte) (err error) {
	a.Raw = append(a.Raw, data...)

	type Alias AuthenticationExtensionsClientInputs

	aux := &struct{ *Alias }{Alias: (*Alias)(a)}

	return json.Unmarshal(data, aux)
}

func (a AuthenticationExtensionsClientInputs) MarshalJSON() (data []byte, err error) {
	type Alias AuthenticationExtensionsClientInputs

	if data, err = json.Marshal(Alias(a)); err != nil {
		return nil, err
	}

	if len(a.Raw) == 0 {
		return data, nil
	}

	var (
		structMap, rawMap map[string]json.RawMessage
	)

	if err = json.Unmarshal(data, &structMap); err != nil {
		return nil, err
	}

	if err = json.Unmarshal(a.Raw, &rawMap); err != nil {
		return nil, err
	}

	merged := rawMap
	for k, v := range structMap {
		merged[k] = v
	}

	return json.Marshal(merged)
}

type HMACGetSecretInput struct {
	Salt1 URLEncodedBase64  `json:"salt1"`
	Salt2 *URLEncodedBase64 `json:"salt2,omitempty"`
}

type AuthenticationExtensionsLargeBlobInputs struct {
	Read  *bool             `json:"read,omitempty"`
	Write *URLEncodedBase64 `json:"write,omitempty"`
}

var (
	_ json.Marshaler   = (*AuthenticationExtensionsClientInputs)(nil)
	_ json.Unmarshaler = (*AuthenticationExtensionsClientInputs)(nil)
	_ Marshallable     = (*AuthenticationExtensionsClientInputs)(nil)
	_ json.Marshaler   = AuthenticationExtensionsClientInputs{}
)
