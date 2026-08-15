package protocol

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/testing/mocks"
)

const (
	typePacked      = "packed-type"
	typeApple       = "apple-type"
	fmtUnregistered = "definitely-not-registered"
)

func TestAttestationFormatValidationHandlerCompound(t *testing.T) {
	t.Run("ShouldReturnValidationErrors", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			return "ok", nil, nil
		}

		base := AttestationObject{
			Format: string(AttestationFormatCompound),
			SubStatements: []NonCompoundAttestationObject{
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
			},
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					AAGUID: make([]byte, 0),
				},
			},
		}

		testCases := []struct {
			name     string
			mutate   func(a AttestationObject) AttestationObject
			expected string
			err      string
		}{
			{
				name: "ShouldRejectInvalidAaguidBytes",
				mutate: func(a AttestationObject) AttestationObject {
					a.AuthData.AttData.AAGUID = []byte{0x01}

					return a
				},
				expected: ErrInvalidAttestation.Type,
				err:      "Error occurred parsing AAGUID",
			},
			{
				// An attStmt which is absent, or which is not an array of sub-statements, is rejected by
				// [AttestationObject.UnmarshalCBOR] and reaches the handler as no sub-statements at all. See
				// TestCompoundAttestation_SpecShapeRejectsMalformedAttStmt for the decoding side.
				name: "ShouldRejectNoSubStatements",
				mutate: func(a AttestationObject) AttestationObject {
					a.SubStatements = nil

					return a
				},
				expected: ErrInvalidAttestation.Type,
				err:      "at least two",
			},
			{
				name: "ShouldRejectAttStmtWithLessThanTwoItems",
				mutate: func(a AttestationObject) AttestationObject {
					a.SubStatements = []NonCompoundAttestationObject{
						{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
					}

					return a
				},
				expected: ErrInvalidAttestation.Type,
				err:      "at least two",
			},
			{
				// A sub-statement whose fmt member is absent decodes to the empty string, which is indistinguishable
				// from one which carries an empty fmt and is rejected the same way.
				name: "ShouldRejectSubStatementMissingFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.SubStatements = []NonCompoundAttestationObject{
						{AttStatement: map[string]any{}},
						{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
					}

					return a
				},
				expected: ErrInvalidAttestation.Type,
				err:      "empty format",
			},
			{
				name: "ShouldRejectSubStatementMissingAttStmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.SubStatements = []NonCompoundAttestationObject{
						{Format: string(AttestationFormatPacked)},
						{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
					}

					return a
				},
				expected: ErrInvalidAttestation.Type,
				err:      "does not have an attestation statement",
			},
			{
				name: "ShouldRejectSubStatementWithCompoundFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.SubStatements = []NonCompoundAttestationObject{
						{Format: string(AttestationFormatCompound), AttStatement: map[string]any{}},
						{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
					}

					return a
				},
				expected: ErrInvalidAttestation.Type,
				err:      "format of compound",
			},
			{
				name: "ShouldRejectSubStatementWithEmptyFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.SubStatements = []NonCompoundAttestationObject{
						{Format: "", AttStatement: map[string]any{}},
						{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
					}

					return a
				},
				expected: ErrInvalidAttestation.Type,
				err:      "empty format",
			},
			{
				name: "ShouldRejectUnsupportedSubStatementFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.SubStatements = []NonCompoundAttestationObject{
						{Format: fmtUnregistered, AttStatement: map[string]any{}},
						{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
					}

					return a
				},
				expected: ErrAttestationFormat.Type,
				err:      "unsupported",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				att := tc.mutate(base)

				attestationType, x5cs, err := attestationFormatValidationHandlerCompound(att, []byte("clientDataHash"), nil, AttestationPolicy{}, SignaturePolicy{})
				require.Error(t, err)
				assert.Empty(t, attestationType)
				assert.Nil(t, x5cs)

				protoErr, ok := err.(*Error)
				require.True(t, ok, "expected *Error, got %T: %v", err, err)

				if tc.expected != "" {
					assert.Equal(t, tc.expected, protoErr.Type)
				}

				combined := protoErr.Details + " " + protoErr.DevInfo
				assert.Contains(t, combined, tc.err)
			})
		}
	})

	t.Run("ShouldCallSubHandlersAndReturnCompound", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		type call struct {
			format  string
			attStmt map[string]any
			auth    AuthenticatorData
			rawAuth []byte
		}

		var calls []call

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			calls = append(calls, call{
				format:  att.Format,
				attStmt: att.AttStatement,
				auth:    att.AuthData,
				rawAuth: att.RawAuthData,
			})

			return typePacked, []any{[]byte("cert1")}, nil
		}

		attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			calls = append(calls, call{
				format:  att.Format,
				attStmt: att.AttStatement,
				auth:    att.AuthData,
				rawAuth: att.RawAuthData,
			})

			return typeApple, []any{[]byte("cert2")}, nil
		}

		auth := AuthenticatorData{
			AttData: AttestedCredentialData{
				AAGUID: make([]byte, 0),
			},
		}

		att := AttestationObject{
			Format:      string(AttestationFormatCompound),
			RawAuthData: []byte{0xAA, 0xBB},
			AuthData:    auth,
			SubStatements: []NonCompoundAttestationObject{
				{
					Format:       string(AttestationFormatPacked),
					AttStatement: map[string]any{"k1": "v1"},
				},
				{
					Format:       string(AttestationFormatApple),
					AttStatement: map[string]any{"k2": "v2"},
				},
			},
		}

		gotType, gotX5Cs, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil, AttestationPolicy{}, SignaturePolicy{})
		require.NoError(t, err)

		// §8.9 returns any combination of the outputs of the successful verification procedures. The type of the
		// first sub-statement is conveyed so the credential isn't recorded as carrying no attestation.
		assert.Equal(t, typePacked, gotType)
		assert.Nil(t, gotX5Cs)

		require.Len(t, calls, 2)
		assert.Equal(t, string(AttestationFormatPacked), calls[0].format)
		assert.Equal(t, string(AttestationFormatApple), calls[1].format)

		assert.True(t, reflect.DeepEqual(calls[0].auth, auth) && reflect.DeepEqual(calls[1].auth, auth),
			"expected auth data to be passed through unchanged, got: %#v", calls)

		assert.True(t, reflect.DeepEqual(calls[0].rawAuth, att.RawAuthData) && reflect.DeepEqual(calls[1].rawAuth, att.RawAuthData),
			"expected raw auth data to be passed through unchanged, got: %#v", calls)
	})

	t.Run("ShouldForwardPolicyToSubHandlersUnchanged", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		type call struct {
			format string
			policy AttestationPolicy
		}

		var calls []call

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, policy AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			calls = append(calls, call{format: att.Format, policy: policy})

			return typePacked, nil, nil
		}

		attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, policy AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			calls = append(calls, call{format: att.Format, policy: policy})

			return typeApple, nil, nil
		}

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{AAGUID: make([]byte, 0)},
			},
			SubStatements: []NonCompoundAttestationObject{
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
				{Format: string(AttestationFormatApple), AttStatement: map[string]any{}},
			},
		}

		// A non-zero policy is deliberate: asserting against the zero value would still pass if the forwarding were
		// replaced by AttestationPolicy{}, which is the exact regression this test exists to catch.
		policy := AttestationPolicy{AndroidKey: AndroidKeyPolicy{AuthorizationScope: AndroidKeyAuthorizationScopeUnion}}

		_, _, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil, policy, SignaturePolicy{})
		require.NoError(t, err)

		require.Len(t, calls, 2)
		assert.Equal(t, policy, calls[0].policy)
		assert.Equal(t, policy, calls[1].policy)
	})

	t.Run("ShouldPropagateSubHandlerError", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		subErr := ErrInvalidAttestation.WithDetails("sub-handler failed")

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			return "", nil, subErr
		}

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{AAGUID: make([]byte, 0)},
			},
			SubStatements: []NonCompoundAttestationObject{
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
			},
		}

		_, _, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil, AttestationPolicy{}, SignaturePolicy{})
		require.Error(t, err)
		assert.True(t, errors.Is(err, subErr))
	})

	t.Run("ShouldWrapMetadataValidationFailure", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		var handlerCalls int

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			handlerCalls++

			return testAttTypeSome, []any{[]byte("cert")}, nil
		}

		ctrl := gomock.NewController(t)

		mds := mocks.NewMockMetadataProvider(ctrl)

		u := uuid.New()

		mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(nil, nil)
		mds.EXPECT().GetValidateEntry(gomock.Any()).Return(true)

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					AAGUID: u[:],
				},
			},
			SubStatements: []NonCompoundAttestationObject{
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
			},
		}

		_, _, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), mds, AttestationPolicy{}, SignaturePolicy{})
		require.Error(t, err)

		protoErr, ok := err.(*Error)
		require.True(t, ok)

		assert.Equal(t, ErrInvalidAttestation.Type, protoErr.Type)
		assert.Contains(t, protoErr.DevInfo, "Error occurred validating metadata")

		assert.Equal(t, 1, handlerCalls)
	})

	t.Run("ShouldNotValidateMetadataWhenMdsIsNil", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		var handlerCalls int

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			handlerCalls++
			return testAttTypeSome, []any{[]byte("cert")}, nil
		}

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					AAGUID: make([]byte, 0),
				},
			},
			SubStatements: []NonCompoundAttestationObject{
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
			},
		}

		gotType, gotX5Cs, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil, AttestationPolicy{}, SignaturePolicy{})
		require.NoError(t, err)

		assert.Equal(t, testAttTypeSome, gotType)
		assert.Nil(t, gotX5Cs)
		assert.Equal(t, 2, handlerCalls)
	})

	// A compound attestation which conveys stmtTypNone suppresses the attestation type validation performed by
	// ValidateMetadata, which skips the check for that value, so the type of a sub-statement must reach it.
	t.Run("ShouldValidateMetadataAgainstTheConveyedAttestationType", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			return string(metadata.BasicFull), nil, nil
		}

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{AAGUID: make([]byte, 0)},
			},
			SubStatements: []NonCompoundAttestationObject{
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
				{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
			},
		}

		gotType, _, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil, AttestationPolicy{}, SignaturePolicy{})
		require.NoError(t, err)
		require.NotEqual(t, stmtTypNone, gotType)

		ctrl := gomock.NewController(t)
		mds := mocks.NewMockMetadataProvider(ctrl)

		entry := &metadata.Entry{
			MetadataStatement: metadata.Statement{
				AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.AttCA},
			},
		}

		mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(entry, nil)
		mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(true)

		protoErr := ValidateMetadata(context.Background(), mds, uuid.Nil, gotType, string(AttestationFormatCompound), nil)
		require.NotNil(t, protoErr)
		assert.Contains(t, protoErr.DevInfo, "is not known to be used by this authenticator")
	})
}

func TestAttestationFormatValidationHandlerCompoundSubStatementScope(t *testing.T) {
	var (
		policyAll = AttestationPolicy{Compound: CompoundPolicy{SubStatementScope: CompoundSubStatementScopeAll}}
		policyAny = AttestationPolicy{Compound: CompoundPolicy{SubStatementScope: CompoundSubStatementScopeAny}}
	)

	t.Run("ShouldAcceptWhenALaterSubStatementVerifies", func(t *testing.T) {
		errPacked := ErrInvalidAttestation.WithDetails("packed sub-statement failed")

		register := func(t *testing.T) {
			t.Helper()

			withFreshAttestationRegistry(t)

			attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
				return "", nil, errPacked
			}

			attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
				return typeApple, nil, nil
			}
		}

		t.Run("Any", func(t *testing.T) {
			register(t)

			// The type recorded against the credential is that of the sub-statement which was verified, not that of
			// the first sub-statement which the all scope conveys.
			attestationType, x5cs, err := attestationFormatValidationHandlerCompound(compoundScopeTestAttestation(nil), []byte("hash"), nil, policyAny, SignaturePolicy{})
			require.NoError(t, err)
			assert.Equal(t, typeApple, attestationType)
			assert.Nil(t, x5cs)
		})

		t.Run("All", func(t *testing.T) {
			register(t)

			_, _, err := attestationFormatValidationHandlerCompound(compoundScopeTestAttestation(nil), []byte("hash"), nil, policyAll, SignaturePolicy{})
			require.Error(t, err)
			assert.True(t, errors.Is(err, errPacked))
		})
	})

	t.Run("ShouldNotVerifySubStatementsAfterTheFirstSuccess", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		var packedCalls, appleCalls int

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			packedCalls++

			return typePacked, nil, nil
		}

		attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			appleCalls++

			return "", nil, ErrInvalidAttestation.WithDetails("apple sub-statement failed")
		}

		attestationType, _, err := attestationFormatValidationHandlerCompound(compoundScopeTestAttestation(nil), []byte("hash"), nil, policyAny, SignaturePolicy{})
		require.NoError(t, err)

		assert.Equal(t, typePacked, attestationType)
		assert.Equal(t, 1, packedCalls)
		assert.Equal(t, 0, appleCalls)
	})

	// A sub-statement which verifies but whose trust path the Metadata Service rejects hasn't been verified in full,
	// so the any scope must move on to the next sub-statement rather than accept it or reject the attestation.
	t.Run("ShouldTreatAMetadataFailureAsASubStatementFailure", func(t *testing.T) {
		u := uuid.New()

		newProvider := func(t *testing.T) metadata.Provider {
			t.Helper()

			ctrl := gomock.NewController(t)

			mds := mocks.NewMockMetadataProvider(ctrl)

			entry := &metadata.Entry{
				MetadataStatement: metadata.Statement{
					AttestationTypes: metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
				},
			}

			mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).Return(entry, nil).AnyTimes()
			mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(true).AnyTimes()
			mds.EXPECT().GetValidateStatus(gomock.Any()).Return(false).AnyTimes()
			mds.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(false).AnyTimes()

			return mds
		}

		register := func(t *testing.T) {
			t.Helper()

			withFreshAttestationRegistry(t)

			// The surrogate type isn't one the metadata entry above declares, so this sub-statement verifies but is
			// rejected by ValidateMetadata.
			attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
				return string(metadata.BasicSurrogate), nil, nil
			}

			attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
				return string(metadata.BasicFull), nil, nil
			}
		}

		t.Run("Any", func(t *testing.T) {
			register(t)

			attestationType, _, err := attestationFormatValidationHandlerCompound(compoundScopeTestAttestation(u[:]), []byte("hash"), newProvider(t), policyAny, SignaturePolicy{})
			require.NoError(t, err)
			assert.Equal(t, string(metadata.BasicFull), attestationType)
		})

		t.Run("All", func(t *testing.T) {
			register(t)

			_, _, err := attestationFormatValidationHandlerCompound(compoundScopeTestAttestation(u[:]), []byte("hash"), newProvider(t), policyAll, SignaturePolicy{})
			require.Error(t, err)

			protoErr, ok := err.(*Error)
			require.True(t, ok)

			assert.Equal(t, ErrInvalidAttestation.Type, protoErr.Type)
			assert.Contains(t, protoErr.DevInfo, "Error occurred validating metadata")
		})
	})

	t.Run("ShouldJoinTheFailuresWhenNoSubStatementVerifies", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		var (
			errPacked = ErrInvalidAttestation.WithDetails("packed sub-statement failed")
			errApple  = ErrInvalidAttestation.WithDetails("apple sub-statement failed")
		)

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			return "", nil, errPacked
		}

		attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
			return "", nil, errApple
		}

		attestationType, x5cs, err := attestationFormatValidationHandlerCompound(compoundScopeTestAttestation(nil), []byte("hash"), nil, policyAny, SignaturePolicy{})
		require.Error(t, err)

		assert.Empty(t, attestationType)
		assert.Nil(t, x5cs)

		protoErr, ok := err.(*Error)
		require.True(t, ok)

		assert.Equal(t, ErrInvalidAttestation.Type, protoErr.Type)

		// Every sub-statement is named alongside its reason so the failure of the set can be diagnosed without
		// re-running the verification of each one.
		assert.Contains(t, protoErr.Details, "packed: packed sub-statement failed")
		assert.Contains(t, protoErr.Details, "apple: apple sub-statement failed")

		assert.True(t, errors.Is(err, errPacked))
		assert.True(t, errors.Is(err, errApple))
	})

	// The scope applies to the outcome of the verification procedures and not to the syntax of the statement, so a
	// sub-statement which can't be verified at all is rejected regardless of the scope in effect.
	t.Run("ShouldRejectUnsupportedSubStatementFormatUnderEveryScope", func(t *testing.T) {
		for _, tc := range []struct {
			name   string
			policy AttestationPolicy
		}{
			{name: "All", policy: policyAll},
			{name: "Any", policy: policyAny},
		} {
			t.Run(tc.name, func(t *testing.T) {
				withFreshAttestationRegistry(t)

				attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider, _ AttestationPolicy, _ SignaturePolicy) (string, []any, error) {
					return typeApple, nil, nil
				}

				att := compoundScopeTestAttestation(nil)
				att.SubStatements = []NonCompoundAttestationObject{
					{Format: fmtUnregistered, AttStatement: map[string]any{}},
					{Format: string(AttestationFormatApple), AttStatement: map[string]any{}},
				}

				_, _, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil, tc.policy, SignaturePolicy{})
				require.Error(t, err)

				protoErr, ok := err.(*Error)
				require.True(t, ok)

				assert.Equal(t, ErrAttestationFormat.Type, protoErr.Type)
				assert.Contains(t, protoErr.DevInfo, "unsupported")
			})
		}
	})
}

func TestCompoundSubStatementFailureReason(t *testing.T) {
	testCases := []struct {
		name     string
		err      error
		expected string
	}{
		{
			name:     "ShouldUseTheDetails",
			err:      ErrInvalidAttestation.WithDetails("the details").WithInfo("the info"),
			expected: "the details",
		},
		{
			name:     "ShouldFallbackToTheDevInfo",
			err:      ErrInvalidAttestation.WithDetails("").WithInfo("the info"),
			expected: "the info",
		},
		{
			name:     "ShouldFallbackToTheType",
			err:      ErrInvalidAttestation.WithDetails("").WithInfo(""),
			expected: ErrInvalidAttestation.Type,
		},
		{
			name:     "ShouldUseTheErrorOfANonProtocolError",
			err:      errors.New("some other error"),
			expected: "some other error",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, compoundSubStatementFailureReason(tc.err))
		})
	}
}

// Supporting functions.

// compoundScopeTestAttestation returns a compound attestation with a packed and an apple sub-statement, in that
// order, which the scope tests register handlers for individually.
func compoundScopeTestAttestation(aaguid []byte) AttestationObject {
	if aaguid == nil {
		aaguid = make([]byte, 0)
	}

	return AttestationObject{
		Format: string(AttestationFormatCompound),
		AuthData: AuthenticatorData{
			AttData: AttestedCredentialData{AAGUID: aaguid},
		},
		SubStatements: []NonCompoundAttestationObject{
			{Format: string(AttestationFormatPacked), AttStatement: map[string]any{}},
			{Format: string(AttestationFormatApple), AttStatement: map[string]any{}},
		},
	}
}

func withFreshAttestationRegistry(t *testing.T) {
	t.Helper()

	orig := make(map[AttestationFormat]attestationFormatValidationHandler, len(attestationRegistry))
	for k, v := range attestationRegistry {
		orig[k] = v
	}

	t.Cleanup(func() {
		for k := range attestationRegistry {
			delete(attestationRegistry, k)
		}

		for k, v := range orig {
			attestationRegistry[k] = v
		}
	})
}
