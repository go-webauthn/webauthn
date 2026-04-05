package webauthn

import (
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
)

func TestAuthenticator_UpdateCounter(t *testing.T) {
	type fields struct {
		AAGUID       []byte
		SignCount    uint32
		CloneWarning bool
	}

	type args struct {
		authDataCount uint32
	}

	testCases := []struct {
		name     string
		fields   fields
		args     args
		expected bool
	}{
		{
			"IncreasedCounter",
			fields{
				AAGUID:       make([]byte, 16),
				SignCount:    1,
				CloneWarning: false,
			},
			args{
				authDataCount: 2,
			},
			false,
		},
		{
			"UnchangedCounter",
			fields{
				AAGUID:       make([]byte, 16),
				SignCount:    1,
				CloneWarning: false,
			},
			args{
				authDataCount: 1,
			},
			true,
		},
		{
			"DecreasedCounter",
			fields{
				AAGUID:       make([]byte, 16),
				SignCount:    2,
				CloneWarning: false,
			},
			args{
				authDataCount: 1,
			},
			true,
		},
		{
			"ZeroCounter",
			fields{
				AAGUID:       make([]byte, 16),
				SignCount:    0,
				CloneWarning: false,
			},
			args{
				authDataCount: 0,
			},
			false,
		},
		{
			"CounterReturnedToZero",
			fields{
				AAGUID:       make([]byte, 16),
				SignCount:    1,
				CloneWarning: false,
			},
			args{
				authDataCount: 0,
			},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			authenticator := &Authenticator{
				AAGUID:       tc.fields.AAGUID,
				SignCount:    tc.fields.SignCount,
				CloneWarning: tc.fields.CloneWarning,
			}

			signCount := authenticator.SignCount
			authenticator.UpdateCounter(tc.args.authDataCount)

			assert.Equal(t, tc.expected, authenticator.CloneWarning)

			if authenticator.CloneWarning {
				assert.Equal(t, signCount, authenticator.SignCount)
			} else {
				assert.Equal(t, tc.args.authDataCount, authenticator.SignCount)
			}
		})
	}
}

func TestSelectAuthenticator(t *testing.T) {
	type args struct {
		att string
		rrk *bool
		uv  string
	}

	testCases := []struct {
		name     string
		args     args
		expected protocol.AuthenticatorSelection
	}{
		{"GenerateCorrectAuthenticatorSelection",
			args{
				att: "platform",
				rrk: protocol.ResidentKeyNotRequired(),
				uv:  "preferred",
			},
			protocol.AuthenticatorSelection{
				AuthenticatorAttachment: protocol.Platform,
				RequireResidentKey:      protocol.ResidentKeyNotRequired(),
				UserVerification:        protocol.VerificationPreferred,
			},
		},
		{"GenerateCorrectAuthenticatorSelection",
			args{
				att: "cross-platform",
				rrk: protocol.ResidentKeyRequired(),
				uv:  "required",
			},
			protocol.AuthenticatorSelection{
				AuthenticatorAttachment: protocol.CrossPlatform,
				RequireResidentKey:      protocol.ResidentKeyRequired(),
				UserVerification:        protocol.VerificationRequired,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, SelectAuthenticator(tc.args.att, tc.args.rrk, tc.args.uv))
		})
	}
}
