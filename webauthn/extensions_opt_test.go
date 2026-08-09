package webauthn

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
)

// testCredentialIDB64 is the base64url encoding of "foo", used as a per-credential PRF map key. The keys of
// evalByCredential are base64url encoded credential IDs.
const testCredentialIDB64 = "Zm9v"

func applyRegistration(t *testing.T, opts ...ExtensionOption) (protocol.AuthenticationExtensions, error) {
	t.Helper()

	var options protocol.PublicKeyCredentialCreationOptions

	err := WithExtensions(opts...)(&options)

	return options.Extensions, err
}

func applyAssertion(t *testing.T, opts ...ExtensionOption) (protocol.AuthenticationExtensions, error) {
	t.Helper()

	var options protocol.PublicKeyCredentialRequestOptions

	err := WithAssertionExtensions(opts...)(&options)

	return options.Extensions, err
}

func TestWithExtensionCredProps(t *testing.T) {
	exts, err := applyRegistration(t, WithExtensionCredProps())

	require.NoError(t, err)
	assert.True(t, exts.CredProps)
}

func TestWithExtensionCredPropsRejectedForAssertion(t *testing.T) {
	_, err := applyAssertion(t, WithExtensionCredProps())

	assert.ErrorContains(t, err, "credProps")
	assert.ErrorContains(t, err, "registration extension")
}

func TestWithExtensionPRFAppliesToBothCeremonies(t *testing.T) {
	values := protocol.PRFValues{First: []byte("salt")}

	registration, err := applyRegistration(t, WithExtensionPRF(values))
	require.NoError(t, err)
	assert.Equal(t, values, registration.PRF.Eval)

	assertion, err := applyAssertion(t, WithExtensionPRF(values))
	require.NoError(t, err)
	assert.Equal(t, values, assertion.PRF.Eval)
}

// TestWithExtensionPRFSupportRequestsTheBareProbe pins the bare "prf":{} probe: it must be emitted as an empty
// dictionary and must be reported by Requested so the resulting 'enabled' output is not rejected as unsolicited.
func TestWithExtensionPRFSupportRequestsTheBareProbe(t *testing.T) {
	for _, tc := range []struct {
		name  string
		apply func(t *testing.T, opts ...ExtensionOption) (protocol.AuthenticationExtensions, error)
	}{
		{"Registration", applyRegistration},
		{"Assertion", applyAssertion},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, opt := range []struct {
				name   string
				option ExtensionOption
			}{
				{"Support", WithExtensionPRFSupport()},
				{"ZeroEval", WithExtensionPRF(protocol.PRFValues{})},
				{"Inputs", WithExtensionInputs(protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{}})},
			} {
				t.Run(opt.name, func(t *testing.T) {
					exts, err := tc.apply(t, opt.option)

					require.NoError(t, err)
					require.NotNil(t, exts.PRF)
					assert.True(t, exts.PRF.IsZero())
					assert.Equal(t, []string{protocol.ExtensionPRF}, exts.Requested())

					data, err := json.Marshal(exts)

					require.NoError(t, err)
					assert.Equal(t, `{"prf":{}}`, string(data))
				})
			}
		})
	}
}

// TestWithExtensionPRFSupportPreservesEval pins that the probe option only ensures the member is present; it never
// discards salts set by another PRF option, in either order.
func TestWithExtensionPRFSupportPreservesEval(t *testing.T) {
	eval := protocol.PRFValues{First: []byte("salt")}

	before, err := applyRegistration(t, WithExtensionPRF(eval), WithExtensionPRFSupport())
	require.NoError(t, err)
	assert.Equal(t, &protocol.PRFInputs{Eval: eval}, before.PRF)

	after, err := applyRegistration(t, WithExtensionPRFSupport(), WithExtensionPRF(eval))
	require.NoError(t, err)
	assert.Equal(t, &protocol.PRFInputs{Eval: eval}, after.PRF)
}

func TestWithExtensionPRFByCredentialRejectedForRegistration(t *testing.T) {
	_, err := applyRegistration(t, WithExtensionPRFByCredential(map[string]protocol.PRFValues{
		testCredentialIDB64: {First: []byte("salt")},
	}, nil))

	assert.ErrorContains(t, err, "prf")
}

func TestWithExtensionLargeBlobCeremonySplit(t *testing.T) {
	registration, err := applyRegistration(t, WithExtensionLargeBlobSupport(protocol.LargeBlobSupportRequired))
	require.NoError(t, err)
	assert.Equal(t, protocol.LargeBlobSupportRequired, registration.LargeBlob.Support)

	_, err = applyAssertion(t, WithExtensionLargeBlobSupport(protocol.LargeBlobSupportRequired))
	assert.ErrorContains(t, err, "largeBlob")

	assertion, err := applyAssertion(t, WithExtensionLargeBlobRead())
	require.NoError(t, err)
	assert.True(t, assertion.LargeBlob.Read)

	_, err = applyRegistration(t, WithExtensionLargeBlobRead())
	assert.ErrorContains(t, err, "largeBlob")
}

func TestWithExtensionGeneric(t *testing.T) {
	exts, err := applyRegistration(t, WithExtension("vendorThing", true))

	require.NoError(t, err)
	assert.Equal(t, map[string]any{"vendorThing": true}, exts.Extra)
}

func TestWithExtensionGenericRejectsModelledIdentifier(t *testing.T) {
	_, err := applyRegistration(t, WithExtension("credProps", true))

	assert.ErrorContains(t, err, "credProps")
	assert.ErrorContains(t, err, "WithExtensionCredProps")
}

// TestWithExtensionGenericRejectsCaseVariantModelledIdentifier pins that the guard is case-insensitive, like both
// JSON codecs. An exact comparison accepted the variant, placed it in Extra, reported it from Requested, and then
// failed the whole options object at marshalling time with a collision error instead of naming the right option.
func TestWithExtensionGenericRejectsCaseVariantModelledIdentifier(t *testing.T) {
	for _, name := range []string{"CredProps", "CREDPROPS", "credprops"} {
		t.Run(name, func(t *testing.T) {
			exts, err := applyRegistration(t, WithExtension(name, true))

			assert.ErrorContains(t, err, name)
			assert.ErrorContains(t, err, "WithExtensionCredProps")
			assert.Empty(t, exts.Extra)
		})
	}
}

func TestWithExtensionInputsIsValidatedForTheCeremony(t *testing.T) {
	// The whole-struct entry point cannot be constrained by the individual options, so the adapter must validate.
	_, err := applyAssertion(t, WithExtensionInputs(protocol.AuthenticationExtensions{CredProps: true}))

	assert.ErrorContains(t, err, "credProps")
}

// TestExtensionOptionAppliesToTheCorrectField covers every per-extension option along two dimensions: the exact
// inputs it produces in the ceremony it belongs to, and its rejection in the ceremony it does not. The expected
// value is the whole [protocol.AuthenticationExtensions] rather than the single field under test, so an option
// that writes the wrong field, or writes more than its own, fails here rather than shipping green.
func TestExtensionOptionAppliesToTheCorrectField(t *testing.T) {
	var (
		eval         = protocol.PRFValues{First: []byte("first"), Second: []byte("second")}
		byCredential = map[string]protocol.PRFValues{testCredentialIDB64: {First: []byte("salt")}}
	)

	testCases := []struct {
		name string
		// ceremony is the one the option belongs to. The empty value means both, in which case the option is
		// applied to each in turn and there is no rejection to assert.
		ceremony protocol.CeremonyType
		// identifier is the extension name the rejection error must name.
		identifier string
		option     ExtensionOption
		expected   protocol.AuthenticationExtensions
	}{
		{
			name:     "WithExtensionPRF",
			option:   WithExtensionPRF(eval),
			expected: protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: eval}},
		},
		{
			name:     "WithExtensionRemoteClientDataJSON",
			option:   WithExtensionRemoteClientDataJSON(`{"origin":"https://example.com"}`),
			expected: protocol.AuthenticationExtensions{RemoteClientDataJSON: `{"origin":"https://example.com"}`},
		},
		{
			name:     "WithExtensionUVM",
			option:   WithExtensionUVM(),
			expected: protocol.AuthenticationExtensions{UVM: true},
		},
		{
			name:       "WithExtensionCredProps",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionCredProps,
			option:     WithExtensionCredProps(),
			expected:   protocol.AuthenticationExtensions{CredProps: true},
		},
		{
			name:       "WithExtensionAppIDExclude",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionAppIDExclude,
			option:     WithExtensionAppIDExclude("https://example.com"),
			expected:   protocol.AuthenticationExtensions{AppIDExclude: "https://example.com"},
		},
		{
			name:       "WithExtensionLargeBlobSupport",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionLargeBlob,
			option:     WithExtensionLargeBlobSupport(protocol.LargeBlobSupportPreferred),
			expected:   protocol.AuthenticationExtensions{LargeBlob: protocol.LargeBlobInputs{Support: protocol.LargeBlobSupportPreferred}},
		},
		{
			name:       "WithExtensionCredentialProtectionPolicy",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionCredentialProtectionPolicy,
			option:     WithExtensionCredentialProtectionPolicy(protocol.CredentialProtectionPolicyUserVerificationRequired, true),
			expected: protocol.AuthenticationExtensions{
				CredentialProtectionPolicy:        protocol.CredentialProtectionPolicyUserVerificationRequired,
				EnforceCredentialProtectionPolicy: true,
			},
		},
		{
			// The enforce flag must not be set when it was not asked for.
			name:       "WithExtensionCredentialProtectionPolicyWithoutEnforcement",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionCredentialProtectionPolicy,
			option:     WithExtensionCredentialProtectionPolicy(protocol.CredentialProtectionPolicyUserVerificationOptional, false),
			expected: protocol.AuthenticationExtensions{
				CredentialProtectionPolicy: protocol.CredentialProtectionPolicyUserVerificationOptional,
			},
		},
		{
			name:       "WithExtensionMinPinLength",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionMinPinLength,
			option:     WithExtensionMinPinLength(),
			expected:   protocol.AuthenticationExtensions{MinPinLength: true},
		},
		{
			name:       "WithExtensionCredBlob",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionCredBlob,
			option:     WithExtensionCredBlob([]byte("blob")),
			expected:   protocol.AuthenticationExtensions{CredBlob: []byte("blob")},
		},
		{
			name:       "WithExtensionHMACCreateSecret",
			ceremony:   protocol.CreateCeremony,
			identifier: protocol.ExtensionHMACCreateSecret,
			option:     WithExtensionHMACCreateSecret(),
			expected:   protocol.AuthenticationExtensions{HMACCreateSecret: true},
		},
		{
			name:       "WithExtensionAppID",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionAppID,
			option:     WithExtensionAppID("https://example.com"),
			expected:   protocol.AuthenticationExtensions{AppID: "https://example.com"},
		},
		{
			name:       "WithExtensionPRFByCredential",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionPRF,
			option:     WithExtensionPRFByCredential(byCredential, nil),
			expected:   protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{EvalByCredential: byCredential}},
		},
		{
			name:       "WithExtensionPRFByCredentialWithFallback",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionPRF,
			option:     WithExtensionPRFByCredential(byCredential, &eval),
			expected:   protocol.AuthenticationExtensions{PRF: &protocol.PRFInputs{Eval: eval, EvalByCredential: byCredential}},
		},
		{
			name:       "WithExtensionLargeBlobRead",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionLargeBlob,
			option:     WithExtensionLargeBlobRead(),
			expected:   protocol.AuthenticationExtensions{LargeBlob: protocol.LargeBlobInputs{Read: true}},
		},
		{
			name:       "WithExtensionLargeBlobWrite",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionLargeBlob,
			option:     WithExtensionLargeBlobWrite([]byte("blob")),
			expected:   protocol.AuthenticationExtensions{LargeBlob: protocol.LargeBlobInputs{Write: []byte("blob")}},
		},
		{
			name:       "WithExtensionGetCredBlob",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionGetCredBlob,
			option:     WithExtensionGetCredBlob(),
			expected:   protocol.AuthenticationExtensions{GetCredBlob: true},
		},
		{
			name:       "WithExtensionHMACGetSecret",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionHMACGetSecret,
			option:     WithExtensionHMACGetSecret([]byte("salt1"), []byte("salt2")),
			expected: protocol.AuthenticationExtensions{
				HMACGetSecret: protocol.HMACGetSecretInputs{Salt1: []byte("salt1"), Salt2: []byte("salt2")},
			},
		},
		{
			// Salt2 is optional and must stay absent rather than becoming an empty non-nil slice.
			name:       "WithExtensionHMACGetSecretWithoutSalt2",
			ceremony:   protocol.AssertCeremony,
			identifier: protocol.ExtensionHMACGetSecret,
			option:     WithExtensionHMACGetSecret([]byte("salt1"), nil),
			expected: protocol.AuthenticationExtensions{
				HMACGetSecret: protocol.HMACGetSecretInputs{Salt1: []byte("salt1")},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.ceremony == "" {
				require.Empty(t, tc.identifier, "an option valid in both ceremonies has no rejection to assert")

				registration, err := applyRegistration(t, tc.option)
				require.NoError(t, err)
				assert.Equal(t, tc.expected, registration)

				assertion, err := applyAssertion(t, tc.option)
				require.NoError(t, err)
				assert.Equal(t, tc.expected, assertion)

				return
			}

			apply, reject := applyRegistration, applyAssertion
			direction := "is a registration extension but was provided for an authentication ceremony"

			if tc.ceremony == protocol.AssertCeremony {
				apply, reject = applyAssertion, applyRegistration
				direction = "is an authentication extension but was provided for a registration ceremony"
			}

			actual, err := apply(t, tc.option)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)

			_, err = reject(t, tc.option)
			assert.EqualError(t, err, fmt.Sprintf("extension %q %s", tc.identifier, direction))
		})
	}
}

// TestWithExtensionPRFByCredentialNilFallbackPreservesEval pins the documented behaviour of a nil fallback: it
// leaves an eval set by an earlier option alone rather than clearing it.
func TestWithExtensionPRFByCredentialNilFallbackPreservesEval(t *testing.T) {
	var (
		eval         = protocol.PRFValues{First: []byte("first")}
		byCredential = map[string]protocol.PRFValues{testCredentialIDB64: {First: []byte("salt")}}
	)

	exts, err := applyAssertion(t, WithExtensionPRF(eval), WithExtensionPRFByCredential(byCredential, nil))

	require.NoError(t, err)
	assert.Equal(t, &protocol.PRFInputs{Eval: eval, EvalByCredential: byCredential}, exts.PRF)
}

// TestWithExtensionInputsReplacesEarlierOptions pins the documented clobbering: WithExtensionInputs assigns the
// whole structure, so anything an earlier option set is discarded rather than merged.
func TestWithExtensionInputsReplacesEarlierOptions(t *testing.T) {
	exts, err := applyRegistration(t,
		WithExtensionCredProps(),
		WithExtensionInputs(protocol.AuthenticationExtensions{MinPinLength: true}),
	)

	require.NoError(t, err)
	assert.False(t, exts.CredProps)
	assert.True(t, exts.MinPinLength)
	assert.Equal(t, protocol.AuthenticationExtensions{MinPinLength: true}, exts)
}

// TestWithExtensionLargeBlobKeyIsReachableAsAnUnmodelledExtension guards the decision recorded on
// [protocol.ExtensionLargeBlobKey]: the identifier has no dedicated option because CTAP 2.1 §12.3 defines no
// client extension input or output for it, so it must route through the generic escape hatch instead.
func TestWithExtensionLargeBlobKeyIsReachableAsAnUnmodelledExtension(t *testing.T) {
	exts, err := applyRegistration(t, WithExtension(protocol.ExtensionLargeBlobKey, true))

	require.NoError(t, err)
	assert.Equal(t, map[string]any{protocol.ExtensionLargeBlobKey: true}, exts.Extra)
	assert.Equal(t, []string{protocol.ExtensionLargeBlobKey}, exts.Requested())
}

func TestWithExtensionsComposes(t *testing.T) {
	exts, err := applyRegistration(t,
		WithExtensionCredProps(),
		WithExtensionMinPinLength(),
		WithExtension("vendorCounter", 1),
	)

	require.NoError(t, err)
	assert.True(t, exts.CredProps)
	assert.True(t, exts.MinPinLength)
	assert.Equal(t, map[string]any{"vendorCounter": 1}, exts.Extra)
}
