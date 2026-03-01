package protocol

import "encoding/json"

type AuthenticationExtensionsClientOutputs struct {
	AppID             *bool                                     `json:"appid,omitempty"`
	GetCredBlob       *URLEncodedBase64                         `json:"getCredBlob,omitempty"`
	HMACGetSecret     *HMACGetSecretOutput                      `json:"hmacGetSecret,omitempty"`
	LargeBlob         *AuthenticationExtensionsLargeBlobOutputs `json:"largeBlob,omitempty"`
	PRF               *AuthenticationExtensionsPRFOutputs       `json:"prf,omitempty"`
	ThirdPartyPayment *bool                                     `json:"thirdPartyPayment,omitempty"`

	Extra map[string]json.RawMessage `json:"-"`
}

func (a *AuthenticationExtensionsClientOutputs) UnmarshalJSON(data []byte) (err error) {
	type alias AuthenticationExtensionsClientOutputs

	var known alias

	if err = json.Unmarshal(data, &known); err != nil {
		return err
	}

	*a = AuthenticationExtensionsClientOutputs(known)

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

func (a AuthenticationExtensionsClientOutputs) MarshalJSON() (data []byte, err error) {
	type alias AuthenticationExtensionsClientOutputs

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
