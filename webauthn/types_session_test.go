package webauthn

import (
	"bytes"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestSessionData_MsgpRoundTrip(t *testing.T) {
	original := newPopulatedSessionData()

	t.Run("MarshalUnmarshalPreservesFields", func(t *testing.T) {
		data, err := original.MarshalMsg(nil)
		require.NoError(t, err)

		var decoded SessionData

		left, err := decoded.UnmarshalMsg(data)
		require.NoError(t, err)
		assert.Empty(t, left)

		assert.Equal(t, original.Challenge, decoded.Challenge)
		assert.Equal(t, original.RelyingPartyID, decoded.RelyingPartyID)
		assert.Equal(t, original.UserID, decoded.UserID)
		assert.Equal(t, original.AllowedCredentialIDs, decoded.AllowedCredentialIDs)
		assert.True(t, original.Expires.Equal(decoded.Expires))
		assert.Equal(t, original.UserVerification, decoded.UserVerification)
		assert.Equal(t, original.CredParams, decoded.CredParams)
		assert.Equal(t, original.Mediation, decoded.Mediation)
		assert.Equal(t, original.Extensions, decoded.Extensions)
		assert.LessOrEqual(t, len(data), original.Msgsize())
	})

	t.Run("EncodeDecodePreservesFields", func(t *testing.T) {
		var buf bytes.Buffer

		require.NoError(t, msgp.Encode(&buf, &original))

		var decoded SessionData

		require.NoError(t, msgp.Decode(&buf, &decoded))
		assert.Equal(t, original.Challenge, decoded.Challenge)
		assert.Equal(t, original.RelyingPartyID, decoded.RelyingPartyID)
		assert.Equal(t, original.UserID, decoded.UserID)
		assert.Equal(t, original.AllowedCredentialIDs, decoded.AllowedCredentialIDs)
		assert.True(t, original.Expires.Equal(decoded.Expires))
		assert.Equal(t, original.UserVerification, decoded.UserVerification)
		assert.Equal(t, original.CredParams, decoded.CredParams)
		assert.Equal(t, original.Mediation, decoded.Mediation)
		assert.Equal(t, original.Extensions, decoded.Extensions)
	})

	t.Run("UnmarshalSkipsUnknownKeys", func(t *testing.T) {
		tiny := []byte{0x81, 0xa3, 'x', 'y', 'z', 0xc3}

		var decoded SessionData

		left, err := decoded.UnmarshalMsg(tiny)
		require.NoError(t, err)
		assert.Empty(t, left)
		assert.Equal(t, SessionData{}, decoded)
	})
}

func TestSessionData_MsgpEmptyVariants(t *testing.T) {
	testCases := []struct {
		name     string
		original SessionData
	}{
		{
			name: "NilAllowedCredentialIDs",
			original: SessionData{
				Challenge:      "c",
				RelyingPartyID: "r",
				UserID:         []byte{0x01},
			},
		},
		{
			name: "EmptyAllowedCredentialIDs",
			original: SessionData{
				Challenge:            "c",
				RelyingPartyID:       "r",
				UserID:               []byte{0x01},
				AllowedCredentialIDs: [][]byte{},
			},
		},
		{
			name: "NilExtensions",
			original: SessionData{
				Challenge:      "c",
				RelyingPartyID: "r",
				UserID:         []byte{0x01},
			},
		},
		{
			name: "EmptyExtensions",
			original: SessionData{
				Challenge:      "c",
				RelyingPartyID: "r",
				UserID:         []byte{0x01},
				Extensions:     protocol.AuthenticationExtensions{},
			},
		},
		{
			name: "NilCredParams",
			original: SessionData{
				Challenge:      "c",
				RelyingPartyID: "r",
				UserID:         []byte{0x01},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.original.MarshalMsg(nil)
			require.NoError(t, err)

			var decoded SessionData

			left, err := decoded.UnmarshalMsg(data)
			require.NoError(t, err)
			assert.Empty(t, left)

			assert.Equal(t, tc.original.Challenge, decoded.Challenge)
			assert.Equal(t, tc.original.RelyingPartyID, decoded.RelyingPartyID)
			assert.Equal(t, tc.original.UserID, decoded.UserID)
			assert.Len(t, decoded.AllowedCredentialIDs, len(tc.original.AllowedCredentialIDs))
			assert.Len(t, decoded.Extensions, len(tc.original.Extensions))
			assert.Len(t, decoded.CredParams, len(tc.original.CredParams))
		})
	}
}

func TestSessionData_MsgpExpiresRoundTrip(t *testing.T) {
	testCases := []struct {
		name string
		t    time.Time
	}{
		{"Epoch", time.Unix(0, 0).UTC()},
		{"Zero", time.Time{}},
		{"RecentUTC", time.Date(2026, time.April, 19, 12, 34, 56, 789000000, time.UTC)},
		{"FarFuture", time.Date(9999, time.December, 31, 23, 59, 59, 0, time.UTC)},
		{"NonUTC", time.Date(2026, time.April, 19, 12, 34, 56, 0, time.FixedZone("AEST", 10*3600))},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			original := SessionData{Expires: tc.t}

			data, err := original.MarshalMsg(nil)
			require.NoError(t, err)

			var (
				decoded SessionData
				left    []byte
			)

			left, err = decoded.UnmarshalMsg(data)
			require.NoError(t, err)
			assert.Empty(t, left)
			assert.True(t, tc.t.Equal(decoded.Expires))
		})
	}
}

func TestSessionData_MsgpEncodeErrorPaths(t *testing.T) {
	v := newPopulatedSessionData()

	data, err := v.MarshalMsg(nil)
	require.NoError(t, err)

	exerciseEncodeMsgErrorPaths(t, &v, data)
}

func TestSessionData_DecodeMsgInvalidTypes(t *testing.T) {
	t.Run("NotAMap", func(t *testing.T) {
		var s SessionData

		_, err := s.UnmarshalMsg(msgpString("not a map"))
		require.Error(t, err)

		var s2 SessionData

		require.Error(t, msgp.Decode(bytes.NewReader(msgpString("not a map")), &s2))
	})

	testCases := []struct {
		name    string
		data    []byte
		wantSub string
	}{
		{"ChallengeAsInt", msgpOneFieldMap("c", msgpInt64(42)), "Challenge"},
		{"RelyingPartyIDAsBool", msgpOneFieldMap("r", msgpBool(true)), "RelyingPartyID"},
		{"UserIDAsInt", msgpOneFieldMap("u", msgpInt64(42)), "UserID"},
		{"AllowedCredentialIDsNotArray", msgpOneFieldMap("allow", msgpBool(true)), "AllowedCredentialIDs"},
		{"AllowedCredentialIDElementNotBytes", msgpOneFieldMap("allow", func() []byte {
			b := msgp.AppendArrayHeader(nil, 1)

			return append(b, msgpBool(true)...)
		}()), "AllowedCredentialIDs"},
		{"ExpiresAsString", msgpOneFieldMap("exp", msgpString("x")), ""},
		{"UserVerificationAsInt", msgpOneFieldMap("uv", msgpInt64(42)), "UserVerification"},
		{"ExtensionsNotMap", msgpOneFieldMap("exts", msgpBool(true)), "Extensions"},
		{"CredParamsNotArray", msgpOneFieldMap("params", msgpBool(true)), "CredParams"},
		{"MediationAsBool", msgpOneFieldMap("cmr", msgpBool(true)), "Mediation"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var s SessionData

			_, err := s.UnmarshalMsg(tc.data)
			require.Error(t, err)

			if tc.wantSub != "" {
				assert.Contains(t, err.Error(), tc.wantSub)
			}

			var s2 SessionData

			streamErr := msgp.Decode(bytes.NewReader(tc.data), &s2)
			require.Error(t, streamErr)

			if tc.wantSub != "" {
				assert.Contains(t, streamErr.Error(), tc.wantSub)
			}
		})
	}
}

func newPopulatedSessionData() SessionData {
	return SessionData{
		Challenge:      "challenge-bytes-b64url",
		RelyingPartyID: "example.com",
		UserID:         []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		AllowedCredentialIDs: [][]byte{
			{0xAA, 0xBB, 0xCC},
			{0xDD, 0xEE, 0xFF, 0x00},
		},
		Expires:          time.Date(2026, time.April, 19, 12, 34, 56, 0, time.UTC),
		UserVerification: protocol.VerificationRequired,
		Extensions: protocol.AuthenticationExtensions{
			"appid":       "https://example.com",
			"credProtect": int64(2),
			"largeBlob":   true,
		},
		CredParams: []protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
		},
		Mediation: protocol.MediationConditional,
	}
}
