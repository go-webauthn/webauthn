package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

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
