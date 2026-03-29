package protocol

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestURLEncodedBase64_MarshalJSON(t *testing.T) {
	testCases := []struct {
		name     string
		have     URLEncodedBase64
		expected string
	}{
		{
			name:     "ShouldMarshalData",
			have:     URLEncodedBase64("test data"),
			expected: `"dGVzdCBkYXRh"`,
		},
		{
			name:     "ShouldMarshalNil",
			have:     nil,
			expected: `null`,
		},
		{
			name:     "ShouldMarshalEmpty",
			have:     URLEncodedBase64{},
			expected: `""`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := tc.have.MarshalJSON()
			require.NoError(t, err)
			assert.Equal(t, tc.expected, string(data))
		})
	}
}

func TestURLEncodedBase64_UnmarshalJSON_Error(t *testing.T) {
	testCases := []struct {
		name string
		data string
		err  string
	}{
		{
			name: "ShouldFailInvalidBase64",
			data: `"not valid base64!!!"`,
			err:  "illegal base64 data at input byte 3",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var e URLEncodedBase64

			assert.EqualError(t, e.UnmarshalJSON([]byte(tc.data)), tc.err)
		})
	}
}

func TestBase64UnmarshalJSON(t *testing.T) {
	type testData struct {
		StringData  string           `json:"string_data"`
		EncodedData URLEncodedBase64 `json:"encoded_data"`
	}

	tests := []struct {
		encodedMessage   string
		expectedTestData testData
	}{
		{
			encodedMessage: "\"" + base64.RawURLEncoding.EncodeToString([]byte("test base64 data")) + "\"",
			expectedTestData: testData{
				StringData:  "test string",
				EncodedData: URLEncodedBase64("test base64 data"),
			},
		},
		{
			encodedMessage: "null",
			expectedTestData: testData{
				StringData:  "test string",
				EncodedData: nil,
			},
		},
	}

	for _, test := range tests {
		raw := fmt.Sprintf(`{"string_data": "test string", "encoded_data": %s}`, test.encodedMessage)
		got := testData{}

		t.Logf("%s\n", raw)

		require.NoError(t, json.NewDecoder(strings.NewReader(raw)).Decode(&got))

		assert.Equal(t, test.expectedTestData.EncodedData, got.EncodedData)
		assert.Equal(t, test.expectedTestData.StringData, got.StringData)
	}
}
