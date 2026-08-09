package protocol

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestCredentialProtectionPolicyValue(t *testing.T) {
	for policy, expected := range map[CredentialProtectionPolicy]uint64{
		CredentialProtectionPolicyUserVerificationOptional:                     1,
		CredentialProtectionPolicyUserVerificationOptionalWithCredentialIDList: 2,
		CredentialProtectionPolicyUserVerificationRequired:                     3,
	} {
		value, ok := policy.Value()

		assert.True(t, ok)
		assert.Equal(t, expected, value)
	}

	value, ok := CredentialProtectionPolicy("nonsense").Value()

	assert.False(t, ok)
	assert.Equal(t, uint64(0), value)
}

func TestAuthenticatorExtensionOutputsVerify(t *testing.T) {
	testCases := []struct {
		name     string
		outputs  *AuthenticatorExtensionOutputs
		session  SessionExtensions
		ceremony CeremonyType
		errs     []string
	}{
		{
			name:     "NotEnforcedIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired},
			ceremony: CreateCeremony,
		},
		{
			name:     "EnforcedWithoutPolicyIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
		},
		{
			name:     "EnforcedAndHonoured",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationRequired)},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
		},
		{
			// An authenticator may apply a stricter policy than the one requested, for instance where its own
			// default exceeds the request.
			name:     "EnforcedAndExceeded",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationRequired)},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationOptional, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
		},
		{
			name:     "EnforcedAndDowngraded",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationOptional)},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "less restrictive"},
		},
		{
			name:     "EnforcedButNotReported",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "did not report the policy"},
		},
		{
			// An authenticator returning no extension outputs at all decodes to a nil receiver.
			name:     "EnforcedWithNoOutputsAtAll",
			outputs:  nil,
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "did not report the policy"},
		},
		{
			name:     "EnforcedWithUnknownPolicy",
			outputs:  &AuthenticatorExtensionOutputs{CredProtect: ptr(CredentialProtectionPolicyUserVerificationRequired)},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicy("nonsense"), EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credentialProtectionPolicy", "not a known policy"},
		},
		{
			// credProtect is a registration extension, so an assertion has nothing to assert.
			name:     "AssertionIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: AssertCeremony,
		},
		{
			// An unrecognised ceremony must fail closed, matching the client output guard.
			name:     "UnknownCeremonyFailsClosed",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: testCeremonyUnknown,
			errs:     []string{"credentialProtectionPolicy", "did not report the policy"},
		},
		{
			name:     "CredBlobStored",
			outputs:  &AuthenticatorExtensionOutputs{CredBlobSet: ptr(true)},
			session:  SessionExtensions{CredBlob: true},
			ceremony: CreateCeremony,
		},
		{
			name:     "CredBlobNotStored",
			outputs:  &AuthenticatorExtensionOutputs{CredBlobSet: ptr(false)},
			session:  SessionExtensions{CredBlob: true},
			ceremony: CreateCeremony,
			errs:     []string{"credBlob", "was not stored"},
		},
		{
			name:     "CredBlobOutcomeMissing",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredBlob: true},
			ceremony: CreateCeremony,
			errs:     []string{"credBlob", "did not report whether it was stored"},
		},
		{
			name:     "CredBlobNotRequested",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
		},
		{
			// credBlob is a registration extension, so the authentication arm must not assert the outcome.
			name:     "CredBlobAssertionIsNotChecked",
			outputs:  &AuthenticatorExtensionOutputs{},
			session:  SessionExtensions{CredBlob: true},
			ceremony: AssertCeremony,
		},
		{
			// Both rules are reported together rather than stopping at the first.
			name:     "EveryProblemIsReported",
			outputs:  &AuthenticatorExtensionOutputs{CredBlobSet: ptr(false)},
			session:  SessionExtensions{CredBlob: true, CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationRequired, EnforceCredentialProtectionPolicy: true},
			ceremony: CreateCeremony,
			errs:     []string{"credBlob", "was not stored", "credentialProtectionPolicy", "did not report the policy"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.outputs.Verify(tc.session, tc.ceremony)

			if len(tc.errs) == 0 {
				assert.NoError(t, err)

				return
			}

			for _, fragment := range tc.errs {
				assert.ErrorContains(t, err, fragment)
			}
		})
	}
}

func TestParseAuthenticatorExtensionOutputs(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{
		"credProtect":  uint64(3),
		"minPinLength": uint64(6),
		"credBlob":     true,
		"hmac-secret":  true,
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)
	require.NotNil(t, have)

	require.NotNil(t, have.CredProtect)
	assert.Equal(t, CredentialProtectionPolicyUserVerificationRequired, *have.CredProtect)

	require.NotNil(t, have.MinPinLength)
	assert.Equal(t, uint(6), *have.MinPinLength)

	require.NotNil(t, have.CredBlobSet)
	assert.True(t, *have.CredBlobSet)
	assert.Nil(t, have.CredBlob)

	require.NotNil(t, have.HMACSecret)
	assert.True(t, *have.HMACSecret)

	assert.Empty(t, have.Extra)
}

func TestParseAuthenticatorExtensionOutputsAssertionForms(t *testing.T) {
	// credBlob and hmac-secret are polymorphic by ceremony: boolean at registration, byte string at assertion.
	data, err := webauthncbor.Marshal(map[string]any{
		"credBlob":    []byte{0x01, 0x02},
		"hmac-secret": []byte{0x03, 0x04},
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, []byte{0x01, 0x02}, have.CredBlob)
	assert.Nil(t, have.CredBlobSet)
	assert.Equal(t, []byte{0x03, 0x04}, have.HMACSecretOutput)
	assert.Nil(t, have.HMACSecret)
}

func TestParseAuthenticatorExtensionOutputsUVM(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{
		"uvm": []any{
			[]any{uint64(2), uint64(4), uint64(2)},
			[]any{uint64(4), uint64(2), uint64(4)},
		},
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, []UserVerificationMethod{
		{UserVerificationMethod: 2, KeyProtectionType: 4, MatcherProtectionType: 2},
		{UserVerificationMethod: 4, KeyProtectionType: 2, MatcherProtectionType: 4},
	}, have.UVM)
}

func TestParseAuthenticatorExtensionOutputsUVMMalformed(t *testing.T) {
	// A uvm output this library cannot represent is preserved in Extra rather than silently truncated, dropped, or
	// failing the whole ceremony.
	testCases := []struct {
		name  string
		value any
	}{
		{
			name:  "FieldOutOfRange",
			value: []any{[]any{uint64(math.MaxUint32) + 1, uint64(4), uint64(2)}},
		},
		{
			name:  "NotAList",
			value: "not-a-list",
		},
		{
			name:  "TooFewFields",
			value: []any{[]any{uint64(2), uint64(4)}},
		},
		{
			name:  "TooManyFields",
			value: []any{[]any{uint64(2), uint64(4), uint64(2), uint64(1)}},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := webauthncbor.Marshal(map[string]any{"uvm": tc.value})
			require.NoError(t, err)

			have, err := ParseAuthenticatorExtensionOutputs(data)
			require.NoError(t, err)

			assert.Nil(t, have.UVM)
			require.Contains(t, have.Extra, "uvm")
		})
	}
}

func TestParseAuthenticatorExtensionOutputsCredProtectIdentifierPrecedence(t *testing.T) {
	// Both identifiers assign CredProtect. A map carrying both must not resolve by map iteration order, which
	// would otherwise make the policy, and therefore the enforcement check in Verify, differ between parses of
	// byte-identical signed data.
	data, err := webauthncbor.Marshal(map[string]any{
		ExtensionCredProtect:                uint64(1),
		ExtensionCredentialProtectionPolicy: uint64(3),
	})
	require.NoError(t, err)

	for range 32 {
		have, err := ParseAuthenticatorExtensionOutputs(data)
		require.NoError(t, err)

		require.NotNil(t, have.CredProtect)
		assert.Equal(t, CredentialProtectionPolicyUserVerificationOptional, *have.CredProtect,
			"the CTAP identifier authenticators echo must win")

		// The losing value stays visible rather than being silently discarded.
		assert.Equal(t, uint64(3), have.Extra[ExtensionCredentialProtectionPolicy])
	}
}

func TestParseAuthenticatorExtensionOutputsRejectsTrailingBytes(t *testing.T) {
	// The extension data is the remainder of the authenticator data, so nothing else bounds it. Anything after the
	// map is unaccounted for and must not be silently ignored.
	data, err := webauthncbor.Marshal(map[string]any{"credProtect": uint64(3)})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(append(append([]byte{}, data...), 0xff))

	assert.Nil(t, have)
	assert.ErrorContains(t, err, "Leftover bytes")

	// A second complete map is the same problem: without the length check the first would silently win.
	have, err = ParseAuthenticatorExtensionOutputs(append(append([]byte{}, data...), data...))

	assert.Nil(t, have)
	assert.ErrorContains(t, err, "Leftover bytes")
}

func TestParseAuthenticatorExtensionOutputsUnknownKey(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{"vendorThing": "x"})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"vendorThing": "x"}, have.Extra)
}

func TestParseAuthenticatorExtensionOutputsWrongTypeIsPreserved(t *testing.T) {
	// A known key carrying an unexpected type is preserved rather than failing the ceremony, so one vendor's odd
	// encoding cannot break registration for that authenticator. Each modelled identifier has its own type
	// assertion, so each one is exercised; a branch which errored instead of falling through to Extra would fail
	// every ceremony that authenticator takes part in.
	testCases := []struct {
		name  string
		key   string
		value any
		field func(o *AuthenticatorExtensionOutputs) any
	}{
		{
			name:  "CredProtectWrongType",
			key:   ExtensionCredProtect,
			value: "three",
			field: func(o *AuthenticatorExtensionOutputs) any { return o.CredProtect },
		},
		{
			// A value outside the three policies CTAP defines is not one this library can name.
			name:  "CredProtectUnknownPolicy",
			key:   ExtensionCredProtect,
			value: uint64(4),
			field: func(o *AuthenticatorExtensionOutputs) any { return o.CredProtect },
		},
		{
			name:  "MinPinLengthWrongType",
			key:   ExtensionMinPinLength,
			value: "six",
			field: func(o *AuthenticatorExtensionOutputs) any { return o.MinPinLength },
		},
		{
			// credBlob is a bool at registration and a byte string at authentication; anything else is neither.
			name:  "CredBlobWrongType",
			key:   ExtensionCredBlob,
			value: uint64(1),
			field: func(o *AuthenticatorExtensionOutputs) any { return o.CredBlobSet },
		},
		{
			name:  "HMACSecretWrongType",
			key:   ExtensionHMACSecret,
			value: uint64(1),
			field: func(o *AuthenticatorExtensionOutputs) any { return o.HMACSecret },
		},
		{
			name:  "UVMFieldWrongType",
			key:   ExtensionUVM,
			value: []any{[]any{"not-an-integer", uint64(4), uint64(2)}},
			field: func(o *AuthenticatorExtensionOutputs) any { return o.UVM },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := webauthncbor.Marshal(map[string]any{tc.key: tc.value})
			require.NoError(t, err)

			have, err := ParseAuthenticatorExtensionOutputs(data)
			require.NoError(t, err)

			assert.Nil(t, tc.field(have), "the modelled field must stay unset")
			require.Contains(t, have.Extra, tc.key, "the value must be preserved rather than dropped")
			assert.Equal(t, tc.value, have.Extra[tc.key])
		})
	}
}

func TestParseAuthenticatorExtensionOutputsMalformed(t *testing.T) {
	// Structurally invalid CBOR is signed data that failed to parse; that is a hard error.
	_, err := ParseAuthenticatorExtensionOutputs([]byte{0xff, 0xff, 0xff})

	assert.Error(t, err)
}
