package protocol

import "encoding/json"

type AuthenticationExtensionsClientOutputs struct {
	AppID             *bool                                     `json:"appid,omitempty"`
	GetCredBlob       *URLEncodedBase64                         `json:"getCredBlob,omitempty"`
	HMACGetSecret     *HMACGetSecretOutput                      `json:"hmacGetSecret,omitempty"`
	LargeBlob         *AuthenticationExtensionsLargeBlobOutputs `json:"largeBlob,omitempty"`
	PRF               *AuthenticationExtensionsPRFOutputs       `json:"prf,omitempty"`
	ThirdPartyPayment *bool                                     `json:"thirdPartyPayment,omitempty"`

	Raw json.RawMessage `json:"-"`
}

func (a *AuthenticationExtensionsClientOutputs) UnmarshalJSON(data []byte) (err error) {
	a.Raw = append(a.Raw, data...)

	type Alias AuthenticationExtensionsClientOutputs

	aux := &struct{ *Alias }{Alias: (*Alias)(a)}

	return json.Unmarshal(data, aux)
}

func (a AuthenticationExtensionsClientOutputs) MarshalJSON() (data []byte, err error) {
	type Alias AuthenticationExtensionsClientOutputs

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

type HMACGetSecretOutput struct {
	Output1 URLEncodedBase64  `json:"output1"`
	Output2 *URLEncodedBase64 `json:"output2,omitempty"`
}

type AuthenticationExtensionsPRFOutputs struct {
	Results *AuthenticationExtensionsPRFValues `json:"results,omitempty"`
}

type AuthenticationExtensionsLargeBlobOutputs struct {
	Blob    *URLEncodedBase64 `json:"blob,omitempty"`
	Written *bool             `json:"written,omitempty"`
}

var (
	_ json.Marshaler   = (*AuthenticationExtensionsClientOutputs)(nil)
	_ json.Unmarshaler = (*AuthenticationExtensionsClientOutputs)(nil)
	_ Marshallable     = (*AuthenticationExtensionsClientOutputs)(nil)
	_ json.Marshaler   = AuthenticationExtensionsClientOutputs{}
)