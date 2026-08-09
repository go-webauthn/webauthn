package protocol

import (
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The verification rules are only as good as what Session records for them, and the read and write arms are
// derived rather than copied, so the derivation is asserted directly.
// testOutputsFromJSON decodes outputs through the real codec, which is the only way to construct the presence
// state a JSON null produces; a struct literal cannot express it.
func testOutputsFromJSON(t *testing.T, data string) (outputs AuthenticationExtensionsClientOutputs) {
	t.Helper()

	require.NoError(t, json.Unmarshal([]byte(data), &outputs))

	return outputs
}

func TestAuthenticationExtensionsSessionDerivation(t *testing.T) {
	t.Run("LargeBlobRead", func(t *testing.T) {
		session := AuthenticationExtensions{LargeBlob: LargeBlobInputs{Read: true}}.Session()

		assert.True(t, session.LargeBlobRead)
		assert.False(t, session.LargeBlobWrite)
	})

	t.Run("LargeBlobWrite", func(t *testing.T) {
		session := AuthenticationExtensions{LargeBlob: LargeBlobInputs{Write: []byte("blob")}}.Session()

		assert.False(t, session.LargeBlobRead)
		assert.True(t, session.LargeBlobWrite)
	})

	t.Run("LargeBlobSupportIsNotAWrite", func(t *testing.T) {
		session := AuthenticationExtensions{LargeBlob: LargeBlobInputs{Support: LargeBlobSupportRequired}}.Session()

		assert.False(t, session.LargeBlobRead)
		assert.False(t, session.LargeBlobWrite)
		assert.Equal(t, LargeBlobSupportRequired, session.LargeBlob)
	})

	t.Run("CredentialProtectionPolicy", func(t *testing.T) {
		session := AuthenticationExtensions{
			CredentialProtectionPolicy:        CredentialProtectionPolicyUserVerificationRequired,
			EnforceCredentialProtectionPolicy: true,
		}.Session()

		assert.Equal(t, CredentialProtectionPolicyUserVerificationRequired, session.CredentialProtectionPolicy)
		assert.True(t, session.EnforceCredentialProtectionPolicy)
	})

	t.Run("ZeroValue", func(t *testing.T) {
		assert.True(t, AuthenticationExtensions{}.Session().IsZero())
	})

	t.Run("CredBlob", func(t *testing.T) {
		session := AuthenticationExtensions{CredBlob: []byte("a blob")}.Session()

		assert.True(t, session.CredBlob)

		// The blob is Relying Party data with no verification role beyond the flag, so it must not be persisted.
		// It is a byte value, so the encoded forms have to be checked as well as the raw one; a raw-only assertion
		// would pass even if the blob were persisted, because it would appear base64url encoded.
		data, err := json.Marshal(session)
		require.NoError(t, err)

		blob := []byte("a blob")

		assert.NotContains(t, string(data), string(blob))
		assert.NotContains(t, string(data), base64.RawURLEncoding.EncodeToString(blob))
		assert.NotContains(t, string(data), base64.URLEncoding.EncodeToString(blob))
	})

	t.Run("EveryNewMemberIsCoveredByIsZero", func(t *testing.T) {
		for name, session := range map[string]SessionExtensions{
			"LargeBlobRead":                     {LargeBlobRead: true},
			"LargeBlobWrite":                    {LargeBlobWrite: true},
			"CredentialProtectionPolicy":        {CredentialProtectionPolicy: CredentialProtectionPolicyUserVerificationOptional},
			"EnforceCredentialProtectionPolicy": {EnforceCredentialProtectionPolicy: true},
			"CredBlob":                          {CredBlob: true},
		} {
			assert.Falsef(t, session.IsZero(), "IsZero must not report %s as empty", name)
		}
	})
}

func TestClientOutputsVerify(t *testing.T) {
	testCases := []struct {
		name     string
		outputs  AuthenticationExtensionsClientOutputs
		session  SessionExtensions
		ceremony CeremonyType
		policy   UnsolicitedOutputPolicy
		errs     []string
	}{
		{
			name:     "Solicited",
			outputs:  AuthenticationExtensionsClientOutputs{CredProps: &CredentialPropertiesOutput{RK: ptr(true)}},
			session:  SessionExtensions{Requested: []string{ExtensionCredProps}},
			ceremony: CreateCeremony,
		},
		{
			name:     "Unsolicited",
			outputs:  AuthenticationExtensionsClientOutputs{CredProps: &CredentialPropertiesOutput{RK: ptr(true)}},
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
			errs:     []string{"credProps"},
		},
		{
			name:     "UnsolicitedIgnored",
			outputs:  AuthenticationExtensionsClientOutputs{CredProps: &CredentialPropertiesOutput{RK: ptr(true)}},
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
			policy:   UnsolicitedOutputPolicyIgnore,
		},
		{
			name:     "UnsolicitedExtra",
			outputs:  AuthenticationExtensionsClientOutputs{Extra: map[string]any{"vendorThing": true}},
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
			errs:     []string{"vendorThing"},
		},
		{
			// A modelled member returned as null leaves the typed field nil. It must still be treated as returned,
			// otherwise a null is a way around the unsolicited check that an unmodelled null does not have.
			name:     "UnsolicitedModelledNull",
			outputs:  testOutputsFromJSON(t, `{"credProps":null}`),
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
			errs:     []string{"credProps"},
		},
		{
			name:     "SolicitedModelledNull",
			outputs:  testOutputsFromJSON(t, `{"credProps":null}`),
			session:  SessionExtensions{Requested: []string{ExtensionCredProps}},
			ceremony: CreateCeremony,
		},
		{
			// The reject policy is what the null must not evade; the ignore policy still ignores it.
			name:     "UnsolicitedModelledNullIgnored",
			outputs:  testOutputsFromJSON(t, `{"credProps":null}`),
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
			policy:   UnsolicitedOutputPolicyIgnore,
		},
		{
			// encoding/json binds a case-variant key to the modelled field, so the null must be recorded under the
			// canonical identifier rather than the key as it was written.
			name:     "UnsolicitedModelledNullCaseVariant",
			outputs:  testOutputsFromJSON(t, `{"CredProps":null}`),
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
			errs:     []string{"credProps"},
		},
		{
			name:     "UnsolicitedRemoteClientDataJSON",
			outputs:  AuthenticationExtensionsClientOutputs{RemoteClientDataJSON: ptr(true)},
			session:  SessionExtensions{},
			ceremony: AssertCeremony,
			errs:     []string{"remoteClientDataJSON"},
		},
		{
			name: "MultipleUnsolicitedAllReported",
			outputs: AuthenticationExtensionsClientOutputs{
				CredProps: &CredentialPropertiesOutput{},
				PRF:       &PRFOutputs{Enabled: ptr(true)},
			},
			session:  SessionExtensions{},
			ceremony: CreateCeremony,
			errs:     []string{"credProps", "prf"},
		},
		{
			name:     "LargeBlobRequiredUnsupported",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Supported: ptr(false)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlob: LargeBlobSupportRequired},
			ceremony: CreateCeremony,
			errs:     []string{"largeBlob", "required"},
		},
		{
			name:     "LargeBlobRequiredAbsent",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlob: LargeBlobSupportRequired},
			ceremony: CreateCeremony,
			errs:     []string{"largeBlob"},
		},
		{
			name:     "LargeBlobRequiredSupported",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Supported: ptr(true)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlob: LargeBlobSupportRequired},
			ceremony: CreateCeremony,
		},
		{
			name:     "LargeBlobPreferredUnsupported",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Supported: ptr(false)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlob: LargeBlobSupportPreferred},
			ceremony: CreateCeremony,
		},
		{
			// The required-support assertion is a registration rule, so an assertion legitimately skips it.
			name:     "LargeBlobRequiredSkippedForAssertion",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Supported: ptr(false)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlob: LargeBlobSupportRequired},
			ceremony: AssertCeremony,
		},
		{
			// An unrecognised ceremony must not skip it, i.e. the guard fails closed.
			name:     "LargeBlobRequiredUnknownCeremony",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Supported: ptr(false)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlob: LargeBlobSupportRequired},
			ceremony: testCeremonyUnknown,
			errs:     []string{"largeBlob", "required"},
		},
		{
			name:     "LargeBlobWritten",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Written: ptr(true)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobWrite: true},
			ceremony: AssertCeremony,
		},
		{
			// A write the client reports as not performed must not yield a successful ceremony.
			name:     "LargeBlobNotWritten",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Written: ptr(false)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobWrite: true},
			ceremony: AssertCeremony,
			errs:     []string{"largeBlob", "was not written"},
		},
		{
			// A client which omits the outcome entirely is treated the same as one reporting failure.
			name:     "LargeBlobWriteOutcomeMissing",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobWrite: true},
			ceremony: AssertCeremony,
			errs:     []string{"largeBlob", "did not report whether it was written"},
		},
		{
			name:     "LargeBlobWriteOutputAbsent",
			outputs:  AuthenticationExtensionsClientOutputs{},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobWrite: true},
			ceremony: AssertCeremony,
			errs:     []string{"largeBlob", "did not report whether it was written"},
		},
		{
			// The read and write arms produce disjoint outputs, so a blob returned for a write is incoherent.
			name:     "LargeBlobWriteReturnedBlob",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Written: ptr(true), Blob: []byte("blob")}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobWrite: true},
			ceremony: AssertCeremony,
			errs:     []string{"largeBlob", "returned a blob it read"},
		},
		{
			name:     "LargeBlobRead",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Blob: []byte("blob")}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobRead: true},
			ceremony: AssertCeremony,
		},
		{
			// A credential with nothing stored yields an empty output, which is a legitimate read result.
			name:     "LargeBlobReadEmpty",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobRead: true},
			ceremony: AssertCeremony,
		},
		{
			name:     "LargeBlobReadReturnedWriteOutcome",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Written: ptr(true)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}, LargeBlobRead: true},
			ceremony: AssertCeremony,
			errs:     []string{"largeBlob", "outcome of a write"},
		},
		{
			// Neither arm was requested, so the registration-shaped output is left to the unsolicited check.
			name:     "LargeBlobNeitherReadNorWrite",
			outputs:  AuthenticationExtensionsClientOutputs{LargeBlob: &LargeBlobOutputs{Written: ptr(false)}},
			session:  SessionExtensions{Requested: []string{ExtensionLargeBlob}},
			ceremony: AssertCeremony,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.outputs.Verify(tc.session, tc.ceremony, tc.policy)

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

// TestClientOutputsVerifyReturnsProtocolError pins that Verify fails with an *Error like every other failure path
// out of the finish step, so a Relying Party which serialises Type, Details and DevInfo does not silently start
// emitting a generic error, while every individual problem stays reachable through the error chain.
func TestClientOutputsVerifyReturnsProtocolError(t *testing.T) {
	testCases := []struct {
		name    string
		outputs AuthenticationExtensionsClientOutputs
		causes  []string
	}{
		{
			// errors.Join wraps even a single error, so the single-cause case is the one that regressed.
			name:    "SingleCause",
			outputs: AuthenticationExtensionsClientOutputs{CredProps: &CredentialPropertiesOutput{}},
			causes:  []string{"credProps"},
		},
		{
			name: "MultipleCauses",
			outputs: AuthenticationExtensionsClientOutputs{
				CredProps: &CredentialPropertiesOutput{},
				PRF:       &PRFOutputs{Enabled: ptr(true)},
			},
			causes: []string{"credProps", "prf"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.outputs.Verify(SessionExtensions{}, CreateCeremony, UnsolicitedOutputPolicyReject)
			require.Error(t, err)

			var protocolError *Error

			require.ErrorAs(t, err, &protocolError)
			assert.Equal(t, ErrBadRequest.Type, protocolError.Type)

			for _, cause := range tc.causes {
				assert.Contains(t, protocolError.Details, cause)
			}

			// The all-problems-reported property survives: the cause is the join, and each individual problem is
			// itself an *Error reachable through it.
			var joined interface{ Unwrap() []error }

			require.ErrorAs(t, err, &joined)

			causes := joined.Unwrap()
			require.Len(t, causes, len(tc.causes))

			for i, cause := range causes {
				var causeError *Error

				require.ErrorAs(t, cause, &causeError)
				assert.Contains(t, causeError.Details, tc.causes[i])
			}
		})
	}
}
