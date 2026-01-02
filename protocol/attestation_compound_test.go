package protocol

import (
	"context"
	"errors"
	"reflect"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
)

type stubMDS struct {
	getEntry                func(ctx context.Context, aaguid uuid.UUID) (*metadata.Entry, error)
	validateEntry           bool
	permitZeroAAGUID        bool
	validateTrustAnchor     bool
	validateStatus          bool
	validateAttestationType bool
	validateStatusReports   func(ctx context.Context, reports []metadata.StatusReport) error
}

func (s stubMDS) GetEntry(ctx context.Context, aaguid uuid.UUID) (*metadata.Entry, error) {
	if s.getEntry != nil {
		return s.getEntry(ctx, aaguid)
	}

	return nil, nil
}

func (s stubMDS) GetValidateEntry(ctx context.Context) bool { return s.validateEntry }

func (s stubMDS) GetValidateEntryPermitZeroAAGUID(ctx context.Context) bool {
	return s.permitZeroAAGUID
}

func (s stubMDS) GetValidateTrustAnchor(ctx context.Context) bool { return s.validateTrustAnchor }

func (s stubMDS) GetValidateStatus(ctx context.Context) bool { return s.validateStatus }

func (s stubMDS) GetValidateAttestationTypes(ctx context.Context) bool {
	return s.validateAttestationType
}

func (s stubMDS) ValidateStatusReports(ctx context.Context, reports []metadata.StatusReport) error {
	if s.validateStatusReports != nil {
		return s.validateStatusReports(ctx, reports)
	}

	return nil
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

func TestAttestationFormatValidationHandlerCompound(t *testing.T) {
	t.Run("ShouldReturnValidationErrors", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider) (string, []any, error) {
			return "ok", nil, nil
		}

		base := AttestationObject{
			Format: string(AttestationFormatCompound),
			AttStatement: map[string]any{
				stmtAttStmt: []any{
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
				},
			},
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					AAGUID: make([]byte, 0),
				},
			},
		}

		testCases := []struct {
			name      string
			mutate    func(a AttestationObject) AttestationObject
			wantType  string
			wantError string
		}{
			{
				name: "ShouldRejectInvalidAaguidBytes",
				mutate: func(a AttestationObject) AttestationObject {
					a.AuthData.AttData.AAGUID = []byte{0x01} // uuid.FromBytes requires 16 bytes
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "Error occurred parsing AAGUID",
			},
			{
				name: "ShouldRejectMissingAttStmt",
				mutate: func(a AttestationObject) AttestationObject {
					delete(a.AttStatement, stmtAttStmt)
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "Compound statement missing attStmt",
			},
			{
				name: "ShouldRejectAttStmtNotArray",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = "nope"
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "Compound statement attStmt isn't an array",
			},
			{
				name: "ShouldRejectAttStmtWithLessThanTwoItems",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = []any{
						map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					}
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "at least two",
			},
			{
				name: "ShouldRejectAttStmtContainingNonObject",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = []any{
						map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
						123,
					}
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "isn't an object",
			},
			{
				name: "ShouldRejectSubStatementMissingFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = []any{
						map[string]any{stmtAttStmt: map[string]any{}},
						map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					}
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "does not have a format",
			},
			{
				name: "ShouldRejectSubStatementMissingAttStmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = []any{
						map[string]any{stmtFmt: string(AttestationFormatPacked)},
						map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					}
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "does not have an attestation statement",
			},
			{
				name: "ShouldRejectSubStatementWithCompoundFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = []any{
						map[string]any{stmtFmt: string(AttestationFormatCompound), stmtAttStmt: map[string]any{}},
						map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					}
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "format of compound",
			},
			{
				name: "ShouldRejectSubStatementWithEmptyFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = []any{
						map[string]any{stmtFmt: "", stmtAttStmt: map[string]any{}},
						map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					}
					return a
				},
				wantType:  ErrInvalidAttestation.Type,
				wantError: "empty format",
			},
			{
				name: "ShouldRejectUnsupportedSubStatementFmt",
				mutate: func(a AttestationObject) AttestationObject {
					a.AttStatement[stmtAttStmt] = []any{
						map[string]any{stmtFmt: "definitely-not-registered", stmtAttStmt: map[string]any{}},
						map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					}
					return a
				},
				wantType:  ErrAttestationFormat.Type,
				wantError: "unsupported",
			},
		}

		for _, tc := range testCases {
			t.Run(tc.name, func(t *testing.T) {
				att := tc.mutate(base)

				attestationType, x5cs, err := attestationFormatValidationHandlerCompound(att, []byte("clientDataHash"), nil)
				require.Error(t, err)
				assert.Empty(t, attestationType)
				assert.Nil(t, x5cs)

				protoErr, ok := err.(*Error)
				require.True(t, ok, "expected *Error, got %T: %v", err, err)

				if tc.wantType != "" {
					assert.Equal(t, tc.wantType, protoErr.Type)
				}

				combined := protoErr.Details + " " + protoErr.DevInfo
				assert.Contains(t, combined, tc.wantError)
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

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider) (string, []any, error) {
			calls = append(calls, call{
				format:  att.Format,
				attStmt: att.AttStatement,
				auth:    att.AuthData,
				rawAuth: att.RawAuthData,
			})
			return "packed-type", []any{[]byte("cert1")}, nil
		}

		attestationRegistry[AttestationFormatApple] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider) (string, []any, error) {
			calls = append(calls, call{
				format:  att.Format,
				attStmt: att.AttStatement,
				auth:    att.AuthData,
				rawAuth: att.RawAuthData,
			})
			return "apple-type", []any{[]byte("cert2")}, nil
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
			AttStatement: map[string]any{
				stmtAttStmt: []any{
					map[string]any{
						stmtFmt:     string(AttestationFormatPacked),
						stmtAttStmt: map[string]any{"k1": "v1"},
					},
					map[string]any{
						stmtFmt:     string(AttestationFormatApple),
						stmtAttStmt: map[string]any{"k2": "v2"},
					},
				},
			},
		}

		gotType, gotX5Cs, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil)
		require.NoError(t, err)

		assert.Equal(t, string(AttestationFormatCompound), gotType)
		assert.Nil(t, gotX5Cs)

		require.Len(t, calls, 2)
		assert.Equal(t, string(AttestationFormatPacked), calls[0].format)
		assert.Equal(t, string(AttestationFormatApple), calls[1].format)

		assert.True(t, reflect.DeepEqual(calls[0].auth, auth) && reflect.DeepEqual(calls[1].auth, auth),
			"expected auth data to be passed through unchanged, got: %#v", calls)

		assert.True(t, reflect.DeepEqual(calls[0].rawAuth, att.RawAuthData) && reflect.DeepEqual(calls[1].rawAuth, att.RawAuthData),
			"expected raw auth data to be passed through unchanged, got: %#v", calls)
	})

	t.Run("ShouldPropagateSubHandlerError", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		subErr := ErrInvalidAttestation.WithDetails("sub-handler failed")

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider) (string, []any, error) {
			return "", nil, subErr
		}

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{AAGUID: make([]byte, 0)},
			},
			AttStatement: map[string]any{
				stmtAttStmt: []any{
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
				},
			},
		}

		_, _, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil)
		require.Error(t, err)
		assert.True(t, errors.Is(err, subErr), "expected returned error to match subErr; got %T: %v", err, err)
	})

	t.Run("ShouldWrapMetadataValidationFailure", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		var handlerCalls int

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider) (string, []any, error) {
			handlerCalls++
			return "some-att-type", []any{[]byte("cert")}, nil
		}

		mds := stubMDS{
			validateEntry: true,
			getEntry: func(ctx context.Context, aaguid uuid.UUID) (*metadata.Entry, error) {
				return nil, nil
			},
		}

		u := uuid.New()

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					AAGUID: u[:],
				},
			},
			AttStatement: map[string]any{
				stmtAttStmt: []any{
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
				},
			},
		}

		_, _, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), mds)
		require.Error(t, err)

		protoErr, ok := err.(*Error)
		require.True(t, ok, "expected *Error, got %T: %v", err, err)

		assert.Equal(t, ErrInvalidAttestation.Type, protoErr.Type)
		assert.Contains(t, protoErr.DevInfo, "Error occurred validating metadata")

		assert.Equal(t, 1, handlerCalls)
	})

	t.Run("ShouldNotValidateMetadataWhenMdsIsNil", func(t *testing.T) {
		withFreshAttestationRegistry(t)

		var handlerCalls int

		attestationRegistry[AttestationFormatPacked] = func(att AttestationObject, clientDataHash []byte, mds metadata.Provider) (string, []any, error) {
			handlerCalls++
			return "some-att-type", []any{[]byte("cert")}, nil
		}

		att := AttestationObject{
			Format: string(AttestationFormatCompound),
			AuthData: AuthenticatorData{
				AttData: AttestedCredentialData{
					AAGUID: make([]byte, 0),
				},
			},
			AttStatement: map[string]any{
				stmtAttStmt: []any{
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
					map[string]any{stmtFmt: string(AttestationFormatPacked), stmtAttStmt: map[string]any{}},
				},
			},
		}

		gotType, gotX5Cs, err := attestationFormatValidationHandlerCompound(att, []byte("hash"), nil)
		require.NoError(t, err)

		assert.Equal(t, string(AttestationFormatCompound), gotType)
		assert.Nil(t, gotX5Cs)
		assert.Equal(t, 2, handlerCalls)
	})
}
