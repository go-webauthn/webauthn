package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testCeremonyUnknown is a CeremonyType which is neither CreateCeremony nor AssertCeremony. The ceremony-applicable
// guards must fail closed against it rather than defaulting to the more permissive branch.
const testCeremonyUnknown CeremonyType = "webauthn.unrecognised"

func TestAuthenticationExtensionsMarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		have     AuthenticationExtensions
		expected string
	}{
		{"Empty", AuthenticationExtensions{}, `{}`},
		{"AppID", AuthenticationExtensions{AppID: "https://example.com"}, `{"appid":"https://example.com"}`},
		{"CredProps", AuthenticationExtensions{CredProps: true}, `{"credProps":true}`},
		{
			"PRFEval",
			AuthenticationExtensions{PRF: &PRFInputs{Eval: PRFValues{First: []byte("abc")}}},
			`{"prf":{"eval":{"first":"YWJj"}}}`,
		},
		{
			"PRFBare",
			AuthenticationExtensions{PRF: &PRFInputs{}},
			`{"prf":{}}`,
		},
		{
			"LargeBlobSupport",
			AuthenticationExtensions{LargeBlob: LargeBlobInputs{Support: LargeBlobSupportRequired}},
			`{"largeBlob":{"support":"required"}}`,
		},
		{
			"Extra",
			AuthenticationExtensions{CredProps: true, Extra: map[string]any{"vendorThing": true}},
			`{"credProps":true,"vendorThing":true}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := json.Marshal(tc.have)

			require.NoError(t, err)
			assert.JSONEq(t, tc.expected, string(data))
		})
	}
}

func TestAuthenticationExtensionsMarshalJSONExtraCollision(t *testing.T) {
	testCases := []struct {
		name string
		have AuthenticationExtensions
		err  string
	}{
		{
			"SetField",
			AuthenticationExtensions{CredProps: true, Extra: map[string]any{"credProps": false}},
			`extra extension "credProps" collides with a modelled extension`,
		},
		{
			// A modelled extension routed through Extra must be rejected even when its own field is zero, so it
			// cannot bypass the typed model. UnmarshalJSON would route the member back to the typed field and drop
			// the Extra entry, so permitting it would also be silently lossy.
			"ZeroField",
			AuthenticationExtensions{Extra: map[string]any{"prf": map[string]any{"eval": map[string]any{"first": "YWJj"}}}},
			`extra extension "prf" collides with a modelled extension`,
		},
		{
			"ZeroFieldBool",
			AuthenticationExtensions{Extra: map[string]any{"credProps": true}},
			`extra extension "credProps" collides with a modelled extension`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := json.Marshal(tc.have)

			assert.ErrorContains(t, err, tc.err)
		})
	}
}

func TestAuthenticationExtensionsExtraCaseInsensitiveCollision(t *testing.T) {
	var have AuthenticationExtensions

	require.NoError(t, json.Unmarshal([]byte(`{"CredProps":true}`), &have))

	// A case-variant of a modelled name must be bound to that field only, never also collected into Extra:
	// otherwise Requested would report the same extension twice under two different spellings.
	assert.True(t, have.CredProps)
	assert.Nil(t, have.Extra)
	assert.Equal(t, []string{ExtensionCredProps}, have.Requested())
}

func TestAuthenticationExtensionsMarshalJSONExtraCollisionCaseVariant(t *testing.T) {
	have := AuthenticationExtensions{Extra: map[string]any{"CredProps": true}}

	_, err := json.Marshal(have)

	assert.ErrorContains(t, err, `extra extension "CredProps" collides with a modelled extension`)
}

func TestAuthenticationExtensionsIsZero(t *testing.T) {
	assert.True(t, AuthenticationExtensions{}.IsZero())
	assert.Nil(t, AuthenticationExtensions{}.Requested())
	assert.False(t, AuthenticationExtensions{CredProps: true}.IsZero())
	assert.False(t, AuthenticationExtensions{Extra: map[string]any{"vendorThing": true}}.IsZero())

	// A zero value must be omitted from the options sent to the client rather than serialised as an empty object.
	creation, err := json.Marshal(PublicKeyCredentialCreationOptions{Challenge: []byte("1234567890123456")})
	require.NoError(t, err)
	assert.NotContains(t, string(creation), "extensions")

	request, err := json.Marshal(PublicKeyCredentialRequestOptions{Challenge: []byte("1234567890123456")})
	require.NoError(t, err)
	assert.NotContains(t, string(request), "extensions")

	// A populated value must still be present.
	creation, err = json.Marshal(PublicKeyCredentialCreationOptions{
		Challenge:  []byte("1234567890123456"),
		Extensions: AuthenticationExtensions{CredProps: true},
	})
	require.NoError(t, err)
	assert.Contains(t, string(creation), `"extensions":{"credProps":true}`)
}

func TestSessionExtensionsIsZero(t *testing.T) {
	assert.True(t, SessionExtensions{}.IsZero())
	assert.False(t, SessionExtensions{Requested: []string{"credProps"}}.IsZero())
	assert.False(t, SessionExtensions{AppID: "a"}.IsZero())
	assert.False(t, SessionExtensions{AppIDExclude: "a"}.IsZero())
	assert.False(t, SessionExtensions{LargeBlob: LargeBlobSupportRequired}.IsZero())
	assert.False(t, SessionExtensions{Extra: map[string]any{"a": 1}}.IsZero())
}

func TestAuthenticationExtensionsSessionClonesExtra(t *testing.T) {
	have := AuthenticationExtensions{Extra: map[string]any{"vendorThing": true}}

	session := have.Session()

	// The session must not alias the live options; mutating one after the begin step must not change the other.
	have.Extra["vendorThing"] = false
	have.Extra["added"] = true

	assert.Equal(t, map[string]any{"vendorThing": true}, session.Extra)
	assert.Nil(t, AuthenticationExtensions{}.Session().Extra)
}

func TestAuthenticationExtensionsMarshalJSONKeyOrderIsStable(t *testing.T) {
	// Marshalling always routes through a map so encoding/json sorts the keys. Output ordering must not depend on
	// whether Extra is populated, otherwise golden comparisons drift.
	withExtra, err := json.Marshal(AuthenticationExtensions{AppID: "a", CredProps: true, Extra: map[string]any{"zz": 1}})
	require.NoError(t, err)

	withoutExtra, err := json.Marshal(AuthenticationExtensions{AppID: "a", CredProps: true})
	require.NoError(t, err)

	assert.Equal(t, `{"appid":"a","credProps":true,"zz":1}`, string(withExtra))
	assert.Equal(t, `{"appid":"a","credProps":true}`, string(withoutExtra))
}

func TestAuthenticationExtensionsUnmarshalJSON(t *testing.T) {
	var have AuthenticationExtensions

	require.NoError(t, json.Unmarshal([]byte(`{"credProps":true,"prf":{"eval":{"first":"YWJj"}},"vendorThing":"x"}`), &have))

	assert.True(t, have.CredProps)
	assert.Equal(t, []byte("abc"), []byte(have.PRF.Eval.First))
	assert.Equal(t, map[string]any{"vendorThing": "x"}, have.Extra)
}

// TestAuthenticationExtensionsPRFBareProbe pins the bare "prf":{} registration probe end to end. The probe is the
// canonical way to ask a client whether the pseudo-random function is available for a credential, so it must be
// emittable, must round trip, must be reported by Requested, and must therefore not be rejected as an unsolicited
// output when the client answers with 'enabled'.
func TestAuthenticationExtensionsPRFBareProbe(t *testing.T) {
	have := AuthenticationExtensions{PRF: &PRFInputs{}}

	require.False(t, have.IsZero())
	assert.Equal(t, []string{ExtensionPRF}, have.Requested())
	assert.NoError(t, have.Validate(CreateCeremony))
	assert.NoError(t, have.Validate(AssertCeremony))

	data, err := json.Marshal(have)
	require.NoError(t, err)
	assert.Equal(t, `{"prf":{}}`, string(data))

	var decoded AuthenticationExtensions

	require.NoError(t, json.Unmarshal(data, &decoded))
	require.NotNil(t, decoded.PRF)
	assert.Equal(t, have, decoded)
	assert.Empty(t, decoded.Extra)

	// The load-bearing consequence: Verify must accept the prf output the probe solicits.
	outputs := AuthenticationExtensionsClientOutputs{PRF: &PRFOutputs{Enabled: ptr(true)}}
	assert.NoError(t, outputs.Verify(have.Session(), CreateCeremony, UnsolicitedOutputPolicyReject))

	// An absent prf member remains absent, and its output remains unsolicited.
	var absent AuthenticationExtensions

	require.NoError(t, json.Unmarshal([]byte(`{}`), &absent))
	assert.Nil(t, absent.PRF)
	assert.Empty(t, absent.Requested())
	assert.ErrorContains(t, outputs.Verify(absent.Session(), CreateCeremony, UnsolicitedOutputPolicyReject), "prf")
}

func TestAuthenticationExtensionsRequestedMatchesMarshalledKeys(t *testing.T) {
	// Requested is hand-written per field. This invariant catches it drifting from the codec.
	testCases := []AuthenticationExtensions{
		{AppID: "a"},
		{AppIDExclude: "a"},
		{CredProps: true},
		{PRF: &PRFInputs{Eval: PRFValues{First: []byte("a")}}},
		{LargeBlob: LargeBlobInputs{Read: true}},
		{RemoteClientDataJSON: "{}"},
		{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired},
		{EnforceCredentialProtectionPolicy: true},
		{MinPinLength: true},
		{CredBlob: []byte("a")},
		{GetCredBlob: true},
		{HMACCreateSecret: true},
		{HMACGetSecret: HMACGetSecretInputs{Salt1: []byte("a")}},
		{UVM: true},
		{Extra: map[string]any{"b": 1, "a": 2}},
	}

	for _, tc := range testCases {
		data, err := json.Marshal(tc)
		require.NoError(t, err)

		var keys map[string]json.RawMessage
		require.NoError(t, json.Unmarshal(data, &keys))

		requested := tc.Requested()

		assert.Len(t, requested, len(keys))

		for _, name := range requested {
			assert.Contains(t, keys, name)
		}
	}
}

func TestAuthenticationExtensionsSession(t *testing.T) {
	have := AuthenticationExtensions{
		AppID:        "https://example.com",
		AppIDExclude: "https://exclude.example.com",
		CredProps:    true,
		PRF:          &PRFInputs{Eval: PRFValues{First: []byte("secret-salt")}},
		LargeBlob:    LargeBlobInputs{Support: LargeBlobSupportRequired, Write: []byte("a large payload")},
		Extra:        map[string]any{"vendorThing": true},
	}

	session := have.Session()

	assert.Equal(t, "https://example.com", session.AppID)
	assert.Equal(t, "https://exclude.example.com", session.AppIDExclude)
	assert.Equal(t, LargeBlobSupportRequired, session.LargeBlob)
	assert.True(t, session.LargeBlobWrite)
	assert.Equal(t, map[string]any{"vendorThing": true}, session.Extra)
	assert.Equal(t, have.Requested(), session.Requested)

	// The per-ceremony PRF salts and the large blob payload are deliberately not persisted.
	data, err := json.Marshal(session)
	require.NoError(t, err)
	assert.NotContains(t, string(data), "secret-salt")
	assert.NotContains(t, string(data), "a large payload")
}

func TestParseAuthenticationExtensions(t *testing.T) {
	have, err := ParseAuthenticationExtensions(map[string]any{
		"credProps":   true,
		"appid":       "https://example.com",
		"vendorThing": "x",
	})

	require.NoError(t, err)
	assert.True(t, have.CredProps)
	assert.Equal(t, "https://example.com", have.AppID)
	assert.Equal(t, map[string]any{"vendorThing": "x"}, have.Extra)
}

func TestParseAuthenticationExtensionsWrongType(t *testing.T) {
	_, err := ParseAuthenticationExtensions(map[string]any{"credProps": "yes"})

	assert.ErrorContains(t, err, "credProps")
}

func TestParseAuthenticationExtensionsRoundTripsThroughMap(t *testing.T) {
	original := AuthenticationExtensions{
		AppID:     "https://example.com",
		CredProps: true,
		PRF:       &PRFInputs{Eval: PRFValues{First: []byte("abc")}},
		Extra:     map[string]any{"vendorThing": true},
	}

	asMap, err := original.Map()
	require.NoError(t, err)

	parsed, err := ParseAuthenticationExtensions(asMap)
	require.NoError(t, err)

	assert.Equal(t, original, parsed)
}

func TestAuthenticationExtensionsValidate(t *testing.T) {
	testCases := []struct {
		name     string
		have     AuthenticationExtensions
		ceremony CeremonyType
		errs     []string
	}{
		{"CredPropsCreation", AuthenticationExtensions{CredProps: true}, CreateCeremony, nil},
		{"CredPropsAssertion", AuthenticationExtensions{CredProps: true}, AssertCeremony, []string{"credProps"}},
		{"AppIDAssertion", AuthenticationExtensions{AppID: "a"}, AssertCeremony, nil},
		{"AppIDCreation", AuthenticationExtensions{AppID: "a"}, CreateCeremony, []string{"appid"}},
		{"AppIDExcludeCreation", AuthenticationExtensions{AppIDExclude: "a"}, CreateCeremony, nil},
		{"AppIDExcludeAssertion", AuthenticationExtensions{AppIDExclude: "a"}, AssertCeremony, []string{"appidExclude"}},
		{
			"CredentialProtectionPolicyCreation",
			AuthenticationExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired},
			CreateCeremony,
			nil,
		},
		{
			"CredentialProtectionPolicyAssertion",
			AuthenticationExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired},
			AssertCeremony,
			[]string{"credentialProtectionPolicy"},
		},
		{"EnforceCredentialProtectionPolicyCreation", AuthenticationExtensions{EnforceCredentialProtectionPolicy: true}, CreateCeremony, nil},
		{
			"EnforceCredentialProtectionPolicyAssertion",
			AuthenticationExtensions{EnforceCredentialProtectionPolicy: true},
			AssertCeremony,
			[]string{"enforceCredentialProtectionPolicy"},
		},
		{"MinPinLengthCreation", AuthenticationExtensions{MinPinLength: true}, CreateCeremony, nil},
		{"MinPinLengthAssertion", AuthenticationExtensions{MinPinLength: true}, AssertCeremony, []string{"minPinLength"}},
		{"CredBlobCreation", AuthenticationExtensions{CredBlob: []byte("a")}, CreateCeremony, nil},
		{"CredBlobAssertion", AuthenticationExtensions{CredBlob: []byte("a")}, AssertCeremony, []string{"credBlob"}},
		{"HMACCreateSecretCreation", AuthenticationExtensions{HMACCreateSecret: true}, CreateCeremony, nil},
		{"HMACCreateSecretAssertion", AuthenticationExtensions{HMACCreateSecret: true}, AssertCeremony, []string{"hmacCreateSecret"}},
		{"GetCredBlobAssertion", AuthenticationExtensions{GetCredBlob: true}, AssertCeremony, nil},
		{"GetCredBlobCreation", AuthenticationExtensions{GetCredBlob: true}, CreateCeremony, []string{"getCredBlob"}},
		{
			"HMACGetSecretAssertion",
			AuthenticationExtensions{HMACGetSecret: HMACGetSecretInputs{Salt1: []byte("a")}},
			AssertCeremony,
			nil,
		},
		{
			"HMACGetSecretCreation",
			AuthenticationExtensions{HMACGetSecret: HMACGetSecretInputs{Salt1: []byte("a")}},
			CreateCeremony,
			[]string{"hmacGetSecret"},
		},
		{
			"EvalByCredentialCreation",
			AuthenticationExtensions{PRF: &PRFInputs{EvalByCredential: map[string]PRFValues{"a": {First: []byte("b")}}}},
			CreateCeremony,
			[]string{"prf"},
		},
		{
			"LargeBlobReadCreation",
			AuthenticationExtensions{LargeBlob: LargeBlobInputs{Read: true}},
			CreateCeremony,
			[]string{"largeBlob"},
		},
		{
			"LargeBlobWriteCreation",
			AuthenticationExtensions{LargeBlob: LargeBlobInputs{Write: []byte("a")}},
			CreateCeremony,
			[]string{"largeBlob"},
		},
		{
			"LargeBlobSupportAssertion",
			AuthenticationExtensions{LargeBlob: LargeBlobInputs{Support: LargeBlobSupportRequired}},
			AssertCeremony,
			[]string{"largeBlob"},
		},
		{
			"LargeBlobReadWriteMutuallyExclusive",
			AuthenticationExtensions{LargeBlob: LargeBlobInputs{Read: true, Write: []byte("a")}},
			AssertCeremony,
			[]string{"largeBlob", "mutually exclusive"},
		},
		{
			"PRFEvalMissingFirst",
			AuthenticationExtensions{PRF: &PRFInputs{Eval: PRFValues{Second: []byte("b")}}},
			CreateCeremony,
			[]string{"first"},
		},
		{
			// PRFValues is shared between eval and evalByCredential, so a rule written against eval alone does
			// not follow the type. Without this the entry marshals "first":null for a required member.
			"PRFEvalByCredentialMissingFirst",
			AuthenticationExtensions{PRF: &PRFInputs{EvalByCredential: map[string]PRFValues{"aabb": {Second: []byte("b")}}}},
			AssertCeremony,
			[]string{"evalByCredential", "aabb", "first"},
		},
		{
			"PRFEvalByCredentialEmptyEntryMissingFirst",
			AuthenticationExtensions{PRF: &PRFInputs{EvalByCredential: map[string]PRFValues{"aabb": {}}}},
			AssertCeremony,
			[]string{"evalByCredential", "first"},
		},
		{
			"PRFEvalByCredentialAllEntriesReported",
			AuthenticationExtensions{PRF: &PRFInputs{EvalByCredential: map[string]PRFValues{
				"aabb": {Second: []byte("b")},
				"ccdd": {Second: []byte("d")},
			}}},
			AssertCeremony,
			[]string{"aabb", "ccdd"},
		},
		{
			"PRFEvalByCredentialFirstPresent",
			AuthenticationExtensions{PRF: &PRFInputs{EvalByCredential: map[string]PRFValues{"aabb": {First: []byte("a")}}}},
			AssertCeremony,
			nil,
		},
		{
			// Likewise salt1, which the IDL marks required, would otherwise marshal as null.
			"HMACGetSecretMissingSalt1",
			AuthenticationExtensions{HMACGetSecret: HMACGetSecretInputs{Salt2: []byte("b")}},
			AssertCeremony,
			[]string{"hmacGetSecret", "salt1"},
		},
		{
			"MultipleProblemsAllReported",
			AuthenticationExtensions{CredProps: true, MinPinLength: true},
			AssertCeremony,
			[]string{"credProps", "minPinLength"},
		},

		// Members valid in both ceremonies: a future over-eager ceremony restriction should fail one of these.
		{"PRFEvalCreation", AuthenticationExtensions{PRF: &PRFInputs{Eval: PRFValues{First: []byte("a")}}}, CreateCeremony, nil},
		{"PRFEvalAssertion", AuthenticationExtensions{PRF: &PRFInputs{Eval: PRFValues{First: []byte("a")}}}, AssertCeremony, nil},
		{"RemoteClientDataJSONCreation", AuthenticationExtensions{RemoteClientDataJSON: "{}"}, CreateCeremony, nil},
		{"RemoteClientDataJSONAssertion", AuthenticationExtensions{RemoteClientDataJSON: "{}"}, AssertCeremony, nil},
		{"UVMCreation", AuthenticationExtensions{UVM: true}, CreateCeremony, nil},
		{"UVMAssertion", AuthenticationExtensions{UVM: true}, AssertCeremony, nil},

		// An unrecognised ceremony is treated as a registration so it fails closed: the authentication-only
		// members are rejected rather than admitted unchecked.
		{"AppIDUnknownCeremony", AuthenticationExtensions{AppID: "a"}, testCeremonyUnknown, []string{"appid"}},
		{"GetCredBlobUnknownCeremony", AuthenticationExtensions{GetCredBlob: true}, testCeremonyUnknown, []string{"getCredBlob"}},
		{
			"HMACGetSecretUnknownCeremony",
			AuthenticationExtensions{HMACGetSecret: HMACGetSecretInputs{Salt1: []byte("a")}},
			testCeremonyUnknown,
			[]string{"hmacGetSecret"},
		},
		{
			"EvalByCredentialUnknownCeremony",
			AuthenticationExtensions{PRF: &PRFInputs{EvalByCredential: map[string]PRFValues{"a": {First: []byte("b")}}}},
			testCeremonyUnknown,
			[]string{"prf"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.have.Validate(tc.ceremony)

			if len(tc.errs) == 0 {
				assert.NoError(t, err)

				return
			}

			require.Error(t, err)

			for _, fragment := range tc.errs {
				assert.ErrorContains(t, err, fragment)
			}
		})
	}
}
