package webauthn

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"

	"github.com/go-webauthn/webauthn/protocol"
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

func TestAuthenticator_MsgpRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		original Authenticator
	}{
		{
			"FullyPopulated",
			Authenticator{
				AAGUID:       bytes.Repeat([]byte{0xAB}, 16),
				SignCount:    1234,
				CloneWarning: true,
				Attachment:   protocol.Platform,
			},
		},
		{
			"CrossPlatformNoCloneWarning",
			Authenticator{
				AAGUID:       bytes.Repeat([]byte{0x01}, 16),
				SignCount:    1,
				CloneWarning: false,
				Attachment:   protocol.CrossPlatform,
			},
		},
		{
			"Zero",
			Authenticator{},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.original.MarshalMsg(nil)
			require.NoError(t, err)

			var decoded Authenticator

			left, err := decoded.UnmarshalMsg(data)
			require.NoError(t, err)
			assert.Empty(t, left, "UnmarshalMsg should consume all bytes")
			assert.Equal(t, tc.original, decoded)
			assert.LessOrEqual(t, len(data), tc.original.Msgsize())

			var buf bytes.Buffer

			require.NoError(t, msgp.Encode(&buf, &tc.original))

			var streamDecoded Authenticator

			require.NoError(t, msgp.Decode(&buf, &streamDecoded))
			assert.Equal(t, tc.original, streamDecoded)
		})
	}

	t.Run("UnmarshalSkipsUnknownKeys", func(t *testing.T) {
		tiny := []byte{0x81, 0xa3, 'x', 'y', 'z', 0xc3}

		var decoded Authenticator

		left, err := decoded.UnmarshalMsg(tiny)
		require.NoError(t, err)
		assert.Empty(t, left)
		assert.Equal(t, Authenticator{}, decoded)
	})
}

func TestAuthenticator_MsgpEncodeErrorPaths(t *testing.T) {
	v := Authenticator{
		AAGUID:       bytes.Repeat([]byte{0xAB}, 16),
		SignCount:    1234,
		CloneWarning: true,
		Attachment:   protocol.Platform,
	}

	data, err := v.MarshalMsg(nil)
	require.NoError(t, err)

	exerciseEncodeMsgErrorPaths(t, &v, data)
}

func TestAuthenticator_DecodeMsgInvalidTypes(t *testing.T) {
	t.Run("NotAMap", func(t *testing.T) {
		var a Authenticator

		_, err := a.UnmarshalMsg(msgpString("not a map"))
		require.Error(t, err)

		var a2 Authenticator

		require.Error(t, msgp.Decode(bytes.NewReader(msgpString("not a map")), &a2))
	})

	testCases := []struct {
		name    string
		data    []byte
		wantSub string
	}{
		{"AAGUIDAsBool", msgpOneFieldMap("aaguid", msgpBool(true)), "AAGUID"},
		{"SignCountAsString", msgpOneFieldMap("sc", msgpString("x")), "SignCount"},
		{"CloneWarningAsInt", msgpOneFieldMap("cw", msgpInt64(42)), "CloneWarning"},
		{"AttachmentAsBool", msgpOneFieldMap("aa", msgpBool(true)), "Attachment"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var a Authenticator

			_, err := a.UnmarshalMsg(tc.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)

			var a2 Authenticator

			streamErr := msgp.Decode(bytes.NewReader(tc.data), &a2)
			require.Error(t, streamErr)
			assert.Contains(t, streamErr.Error(), tc.wantSub)
		})
	}
}
