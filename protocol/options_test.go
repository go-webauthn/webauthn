package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestPublicKeyCredentialRequestOptions_GetAllowedCredentialIDs(t *testing.T) {
	type fields struct {
		Challenge          URLEncodedBase64
		Timeout            int
		RelyingPartyID     string
		AllowedCredentials []CredentialDescriptor
		UserVerification   UserVerificationRequirement
		Extensions         AuthenticationExtensions
	}

	testCases := []struct {
		name     string
		fields   fields
		expected [][]byte
	}{
		{
			"CorrectCredentialIDs",
			fields{
				Challenge: URLEncodedBase64([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
				Timeout:   60,
				AllowedCredentials: []CredentialDescriptor{
					{
						Type: PublicKeyCredentialType, CredentialID: []byte("1234"), Transport: []AuthenticatorTransport{"usb"},
					},
				},
				RelyingPartyID:   "test.org",
				UserVerification: VerificationPreferred,
				Extensions:       AuthenticationExtensions{},
			},
			[][]byte{
				[]byte("1234"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := &PublicKeyCredentialRequestOptions{
				Challenge:          tc.fields.Challenge,
				Timeout:            tc.fields.Timeout,
				RelyingPartyID:     tc.fields.RelyingPartyID,
				AllowedCredentials: tc.fields.AllowedCredentials,
				UserVerification:   tc.fields.UserVerification,
				Extensions:         tc.fields.Extensions,
			}

			assert.Equal(t, tc.expected, options.GetAllowedCredentialIDs())
		})
	}
}

func TestCredentialDescriptor_SignalUnknownCredential(t *testing.T) {
	testCases := []struct {
		name         string
		rpid         string
		have         *CredentialDescriptor
		expected     *SignalUnknownCredential
		expectedJSON string
	}{
		{
			"ShouldHandleStandard",
			"example.com",
			&CredentialDescriptor{
				CredentialID: URLEncodedBase64("1234"),
			},
			&SignalUnknownCredential{
				CredentialID: URLEncodedBase64("1234"),
				RPID:         "example.com",
			},
			`{"credentialId":"MTIzNA","rpId":"example.com"}`,
		},
		{
			"ShouldHandleNoID",
			"example.com",
			&CredentialDescriptor{},
			&SignalUnknownCredential{
				RPID: "example.com",
			},
			`{"credentialId":null,"rpId":"example.com"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.SignalUnknownCredential(tc.rpid)

			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}

func TestCredentialParameter_MsgpRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		original CredentialParameter
	}{
		{"BothFieldsSet", CredentialParameter{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
		{"RS256", CredentialParameter{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256}},
		{"Ed25519", CredentialParameter{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA}},
		{"TypeOnly", CredentialParameter{Type: PublicKeyCredentialType}},
		{"AlgorithmOnly", CredentialParameter{Algorithm: webauthncose.AlgES256}},
		{"BothOmitted", CredentialParameter{}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.original.MarshalMsg(nil)
			require.NoError(t, err)

			var decoded CredentialParameter

			left, err := decoded.UnmarshalMsg(data)
			require.NoError(t, err)
			assert.Empty(t, left)
			assert.Equal(t, tc.original, decoded)
			assert.LessOrEqual(t, len(data), tc.original.Msgsize())

			var buf bytes.Buffer

			require.NoError(t, msgp.Encode(&buf, tc.original))

			var streamDecoded CredentialParameter

			require.NoError(t, msgp.Decode(&buf, &streamDecoded))
			assert.Equal(t, tc.original, streamDecoded)
		})
	}
}

func TestCredentialParameter_MsgpOmitEmpty(t *testing.T) {
	testCases := []struct {
		name    string
		value   CredentialParameter
		wantLen int
	}{
		{"BothPresent", CredentialParameter{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}, 2},
		{"TypeOnly", CredentialParameter{Type: PublicKeyCredentialType}, 1},
		{"AlgorithmOnly", CredentialParameter{Algorithm: webauthncose.AlgES256}, 1},
		{"BothOmitted", CredentialParameter{}, 0},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.value.MarshalMsg(nil)
			require.NoError(t, err)

			size, _, err := msgp.ReadMapHeaderBytes(data)
			require.NoError(t, err)
			assert.Equal(t, uint32(tc.wantLen), size)
		})
	}
}

func TestCredentialParameter_MsgpUnmarshalSkipsUnknownKeys(t *testing.T) {
	t.Run("AlongsideKnown", func(t *testing.T) {
		original := CredentialParameter{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}

		data, err := original.MarshalMsg(nil)
		require.NoError(t, err)

		size, rest, err := msgp.ReadMapHeaderBytes(data)
		require.NoError(t, err)

		spliced := msgp.AppendMapHeader(nil, size+1)
		spliced = msgp.AppendString(spliced, "xyz")
		spliced = msgp.AppendBool(spliced, true)
		spliced = append(spliced, rest...)

		var decoded CredentialParameter

		left, err := decoded.UnmarshalMsg(spliced)
		require.NoError(t, err)
		assert.Empty(t, left)
		assert.Equal(t, original, decoded)
	})

	t.Run("OnlyUnknown", func(t *testing.T) {
		tiny := []byte{0x81, 0xa3, 'x', 'y', 'z', 0xc3}

		var decoded CredentialParameter

		left, err := decoded.UnmarshalMsg(tiny)
		require.NoError(t, err)
		assert.Empty(t, left)
		assert.Equal(t, CredentialParameter{}, decoded)

		var streamDecoded CredentialParameter

		require.NoError(t, msgp.Decode(bytes.NewReader(tiny), &streamDecoded))
		assert.Equal(t, CredentialParameter{}, streamDecoded)
	})
}

func TestCredentialParameter_DecodeMsgInvalidTypes(t *testing.T) {
	t.Run("NotAMap", func(t *testing.T) {
		var c CredentialParameter

		_, err := c.UnmarshalMsg(msgpString("not a map"))
		require.Error(t, err)

		var c2 CredentialParameter

		require.Error(t, msgp.Decode(bytes.NewReader(msgpString("not a map")), &c2))
	})

	testCases := []struct {
		name    string
		data    []byte
		wantSub string
	}{
		{"TypeAsInt", msgpOneFieldMap("typ", msgpInt64(42)), "Type"},
		{"TypeAsBool", msgpOneFieldMap("typ", msgpBool(true)), "Type"},
		{"AlgorithmAsString", msgpOneFieldMap("alg", msgpString("not an int")), "Algorithm"},
		{"AlgorithmAsBool", msgpOneFieldMap("alg", msgpBool(true)), "Algorithm"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var c CredentialParameter

			_, err := c.UnmarshalMsg(tc.data)
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantSub)

			var c2 CredentialParameter

			streamErr := msgp.Decode(bytes.NewReader(tc.data), &c2)
			require.Error(t, streamErr)
			assert.Contains(t, streamErr.Error(), tc.wantSub)
		})
	}
}

func TestCredentialParameter_MsgpEncodeErrorPaths(t *testing.T) {
	v := CredentialParameter{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}

	data, err := v.MarshalMsg(nil)
	require.NoError(t, err)

	exerciseEncodeMsgErrorPaths(t, v, data)
}

type failingWriter struct {
	limit int
	count int
}

func (w *failingWriter) Write(p []byte) (int, error) {
	remaining := w.limit - w.count
	if remaining <= 0 {
		return 0, errors.New("failingWriter: exhausted")
	}

	if len(p) > remaining {
		w.count = w.limit

		return remaining, errors.New("failingWriter: exhausted")
	}

	w.count += len(p)

	return len(p), nil
}

func exerciseEncodeMsgErrorPaths(t *testing.T, enc msgp.Encodable, marshalled []byte) {
	t.Helper()

	for limit := 0; limit <= len(marshalled); limit++ {
		fw := &failingWriter{limit: limit}
		wr := msgp.NewWriterSize(fw, 18)

		err := enc.EncodeMsg(wr)
		if err == nil {
			err = wr.Flush()
		}

		if limit < len(marshalled) {
			require.Errorf(t, err, "EncodeMsg should fail when underlying writer errors after %d bytes", limit)
		} else {
			require.NoError(t, err)
		}
	}
}

func msgpOneFieldMap(key string, value []byte) []byte {
	b := msgp.AppendMapHeader(nil, 1)
	b = msgp.AppendString(b, key)

	return append(b, value...)
}

func msgpBool(v bool) []byte     { return msgp.AppendBool(nil, v) }
func msgpInt64(v int64) []byte   { return msgp.AppendInt64(nil, v) }
func msgpString(v string) []byte { return msgp.AppendString(nil, v) }
