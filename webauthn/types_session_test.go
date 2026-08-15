package webauthn

import (
	"bytes"
	"reflect"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestSessionData_GetRelyingPartyID(t *testing.T) {
	testCases := []struct {
		name     string
		session  SessionData
		fallback string
		expected string
	}{
		{
			name:     "ShouldUseSessionValue",
			session:  SessionData{RelyingPartyID: "a.example.com"},
			fallback: "example.com",
			expected: "a.example.com",
		},
		{
			name:     "ShouldFallBackWhenSessionValueIsEmpty",
			session:  SessionData{},
			fallback: "example.com",
			expected: "example.com",
		},
		{
			name:     "ShouldFallBackToEmptyWhenNeitherIsSet",
			session:  SessionData{},
			expected: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.session.GetRelyingPartyID(tc.fallback))
		})
	}
}

func TestSessionData_GetOrigins(t *testing.T) {
	testCases := []struct {
		name     string
		session  SessionData
		fallback []string
		expected []string
	}{
		{
			name:     "ShouldNarrowToTheSessionValue",
			session:  SessionData{Origin: "https://a.example.com"},
			fallback: []string{"https://a.example.com", "https://b.example.com"},
			expected: []string{"https://a.example.com"},
		},
		{
			name:     "ShouldFallBackWhenSessionValueIsEmpty",
			session:  SessionData{},
			fallback: []string{"https://a.example.com", "https://b.example.com"},
			expected: []string{"https://a.example.com", "https://b.example.com"},
		},
		{
			name:     "ShouldFallBackToNilWhenNeitherIsSet",
			session:  SessionData{},
			expected: nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.session.GetOrigins(tc.fallback))
		})
	}
}

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
		assert.Equal(t, original.Origin, decoded.Origin)
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
		assert.Equal(t, original.Origin, decoded.Origin)
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
			name: "ZeroExtensions",
			original: SessionData{
				Challenge:      "c",
				RelyingPartyID: "r",
				UserID:         []byte{0x01},
			},
		},
		{
			name: "PopulatedExtensions",
			original: SessionData{
				Challenge:      "c",
				RelyingPartyID: "r",
				UserID:         []byte{0x01},
				Extensions: protocol.SessionExtensions{
					Requested: []string{"appid"},
					AppID:     "https://example.com",
				},
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
			assert.Equal(t, tc.original.Extensions, decoded.Extensions)
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

func TestSessionDataUnmarshalMsgLeavesExtensionsWhenOmitted(t *testing.T) {
	// SessionData documents that Extensions, unlike the other members, is not reset when the encoded payload omits
	// it, so a reused destination keeps the previous ceremony's extension state. This pins that behaviour: it is
	// the reason the documentation tells Relying Parties to decode into a fresh SessionData, and a silent change
	// either way would invalidate that advice.
	payload := msgp.AppendMapHeader(nil, 1)
	payload = msgp.AppendString(payload, "c")
	payload = msgp.AppendString(payload, "a-new-challenge")

	decoded := SessionData{
		Extensions: protocol.SessionExtensions{
			Requested: []string{protocol.ExtensionAppID},
			AppID:     "https://previous.example.com",
		},
	}

	left, err := decoded.UnmarshalMsg(payload)
	require.NoError(t, err)
	assert.Empty(t, left)

	assert.Equal(t, "a-new-challenge", decoded.Challenge)
	assert.Equal(t, "https://previous.example.com", decoded.Extensions.AppID,
		"Extensions is not cleared by a payload which omits it; decode into a fresh SessionData")
}

func TestSessionExtensionsShadowMatches(t *testing.T) {
	// A compile-time conversion in both directions proves the shadow struct the msgp generator uses stays
	// field-for-field identical to the protocol type.
	var (
		shadow sessionExtensions
		actual protocol.SessionExtensions
	)

	assert.Equal(t, protocol.SessionExtensions(shadow), actual)
	assert.Equal(t, sessionExtensions(actual), shadow)

	assert.Equal(t, reflect.TypeOf(shadow).NumField(), reflect.TypeOf(actual).NumField())
}

func newPopulatedSessionData() SessionData {
	return SessionData{
		Challenge:      "challenge-bytes-b64url",
		RelyingPartyID: "example.com",
		Origin:         "https://a.example.com",
		UserID:         []byte{0x01, 0x02, 0x03, 0x04, 0x05},
		AllowedCredentialIDs: [][]byte{
			{0xAA, 0xBB, 0xCC},
			{0xDD, 0xEE, 0xFF, 0x00},
		},
		Expires:          time.Date(2026, time.April, 19, 12, 34, 56, 0, time.UTC),
		UserVerification: protocol.VerificationRequired,
		Extensions: protocol.SessionExtensions{
			Requested:                         []string{"credProps", "largeBlob"},
			LargeBlob:                         protocol.LargeBlobSupportPreferred,
			LargeBlobRead:                     true,
			CredentialProtectionPolicy:        protocol.CredentialProtectionPolicyUserVerificationRequired,
			EnforceCredentialProtectionPolicy: true,
			CredBlob:                          true,
			Extra:                             map[string]any{"vendorThing": int64(2)},
		},
		CredParams: []protocol.CredentialParameter{
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
			{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
		},
		Mediation: protocol.MediationConditional,
	}
}
