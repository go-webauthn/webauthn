package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientOutputsUnmarshalJSON(t *testing.T) {
	var have AuthenticationExtensionsClientOutputs

	require.NoError(t, json.Unmarshal([]byte(`{
		"appid": true,
		"credProps": {"rk": false},
		"prf": {"enabled": true, "results": {"first": "YWJj"}},
		"largeBlob": {"supported": true},
		"vendorThing": 7
	}`), &have))

	require.NotNil(t, have.AppID)
	assert.True(t, *have.AppID)

	require.NotNil(t, have.CredProps)
	require.NotNil(t, have.CredProps.RK)
	assert.False(t, *have.CredProps.RK, "rk false must be distinguishable from absent")

	require.NotNil(t, have.PRF)
	assert.True(t, *have.PRF.Enabled)
	assert.Equal(t, []byte("abc"), []byte(have.PRF.Results.First))

	require.NotNil(t, have.LargeBlob)
	assert.True(t, *have.LargeBlob.Supported)

	assert.Equal(t, map[string]any{"vendorThing": float64(7)}, have.Extra)
}

func TestClientOutputsAbsentIsNotFalse(t *testing.T) {
	var have AuthenticationExtensionsClientOutputs

	require.NoError(t, json.Unmarshal([]byte(`{}`), &have))

	assert.Nil(t, have.AppID)
	assert.Nil(t, have.CredProps)
	assert.Empty(t, have.Present())
}

func TestClientOutputsPresent(t *testing.T) {
	have := AuthenticationExtensionsClientOutputs{
		AppID:     ptr(false),
		CredProps: &CredentialPropertiesOutput{RK: ptr(true)},
		Extra:     map[string]any{"vendorThing": 1},
	}

	assert.Equal(t, []string{ExtensionAppID, ExtensionCredProps, "vendorThing"}, have.Present())
}

func TestClientOutputsRoundTrip(t *testing.T) {
	original := AuthenticationExtensionsClientOutputs{
		PRF:   &PRFOutputs{Enabled: ptr(true)},
		Extra: map[string]any{"vendorThing": "x"},
	}

	data, err := json.Marshal(original)
	require.NoError(t, err)

	var decoded AuthenticationExtensionsClientOutputs
	require.NoError(t, json.Unmarshal(data, &decoded))

	assert.Equal(t, original, decoded)
}

func TestClientOutputsAppIDWrongType(t *testing.T) {
	var outputs AuthenticationExtensionsClientOutputs

	err := json.Unmarshal([]byte(`{"appid":"not-a-bool"}`), &outputs)

	var typeErr *json.UnmarshalTypeError
	require.ErrorAs(t, err, &typeErr, "must fail with the standard library's typed unmarshal error, not merely some error mentioning the field")
	assert.Equal(t, "appid", typeErr.Field)
}

func TestClientOutputsAppIDWrongTypeCaseVariant(t *testing.T) {
	// encoding/json binds "appID" to the appid field via its case-insensitive tag fallback before UnmarshalJSON's
	// Extra split ever runs, so a case-variant key with an incompatible value still fails the whole unmarshal
	// rather than being collected into Extra. This is inherent to encoding/json v1 (see the type doc comment) and
	// must not be silently hidden by, say, a fixture rename that only exercises the exact-case key.
	var outputs AuthenticationExtensionsClientOutputs

	err := json.Unmarshal([]byte(`{"appID":"not-a-bool"}`), &outputs)

	var typeErr *json.UnmarshalTypeError
	require.ErrorAs(t, err, &typeErr)
}

func TestClientOutputsExtraCaseInsensitiveCollision(t *testing.T) {
	var have AuthenticationExtensionsClientOutputs

	require.NoError(t, json.Unmarshal([]byte(`{"appID":true}`), &have))

	require.NotNil(t, have.AppID)
	assert.True(t, *have.AppID)

	// A case-variant of a modelled name must be bound to that field only, never also collected into Extra: the
	// unsolicited output check in Present must not report the same output twice under two different spellings.
	assert.Nil(t, have.Extra)
	assert.Equal(t, []string{ExtensionAppID}, have.Present())
}

func TestClientOutputsMarshalJSONExtraCollisionCaseVariant(t *testing.T) {
	have := AuthenticationExtensionsClientOutputs{
		Extra: map[string]any{"CredProps": true},
	}

	_, err := json.Marshal(have)

	assert.ErrorContains(t, err, `extra extension "CredProps" collides with a modelled extension`)
}

func TestClientOutputsIsZero(t *testing.T) {
	assert.True(t, AuthenticationExtensionsClientOutputs{}.IsZero())
	assert.Empty(t, AuthenticationExtensionsClientOutputs{}.Present())
	assert.False(t, AuthenticationExtensionsClientOutputs{AppID: ptr(false)}.IsZero())
	assert.False(t, AuthenticationExtensionsClientOutputs{Extra: map[string]any{"vendorThing": true}}.IsZero())

	// A zero value must be omitted from a marshalled credential rather than serialised as an empty object; without
	// the omitzero tag this would always emit "clientExtensionResults":{}.
	data, err := json.Marshal(ParsedPublicKeyCredential{ParsedCredential: ParsedCredential{ID: "a", Type: "public-key"}})
	require.NoError(t, err)
	assert.NotContains(t, string(data), "clientExtensionResults")

	// A populated value must still be present.
	data, err = json.Marshal(ParsedPublicKeyCredential{
		ParsedCredential:       ParsedCredential{ID: "a", Type: "public-key"},
		ClientExtensionResults: AuthenticationExtensionsClientOutputs{AppID: ptr(true)},
	})
	require.NoError(t, err)
	assert.Contains(t, string(data), `"clientExtensionResults":{"appid":true}`)
}

func TestClientOutputsMap(t *testing.T) {
	// Map is the untyped view callers migrating from the previous map representation use, so it has to agree with
	// the marshalled JSON, including the merged Extra members.
	outputs := AuthenticationExtensionsClientOutputs{
		AppID:     ptr(true),
		CredProps: &CredentialPropertiesOutput{RK: ptr(false)},
		Extra:     map[string]any{"vendorThing": "x"},
	}

	have, err := outputs.Map()
	require.NoError(t, err)

	assert.Equal(t, map[string]any{
		"appid":       true,
		"credProps":   map[string]any{"rk": false},
		"vendorThing": "x",
	}, have)
}

func TestClientOutputsMapPropagatesMarshalError(t *testing.T) {
	// Map goes through MarshalJSON, so the collision check it performs has to surface rather than yielding a
	// partial map.
	outputs := AuthenticationExtensionsClientOutputs{Extra: map[string]any{ExtensionCredProps: true}}

	have, err := outputs.Map()

	assert.Nil(t, have)
	assert.ErrorContains(t, err, "collides with a modelled extension")
}

func TestClientOutputsMarshalJSONExtraValueError(t *testing.T) {
	// An Extra value which cannot be marshalled is reported against the extension that carries it, rather than
	// failing with an error that does not say which member was at fault.
	_, err := AuthenticationExtensionsClientOutputs{Extra: map[string]any{"vendorThing": make(chan int)}}.MarshalJSON()

	assert.ErrorContains(t, err, "extension outputs")
	assert.ErrorContains(t, err, `"vendorThing"`)
}
