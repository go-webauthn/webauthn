package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

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

		err := json.NewDecoder(strings.NewReader(raw)).Decode(&got)
		if err != nil {
			t.Fatalf("error decoding JSON: %v", err)
		}

		if !bytes.Equal(test.expectedTestData.EncodedData, got.EncodedData) {
			t.Fatalf("invalid URLEncodedBase64 data received: expected %s got %s", test.expectedTestData.EncodedData, got.EncodedData)
		}

		if test.expectedTestData.StringData != got.StringData {
			t.Fatalf("invalid string data received: expected %s got %s", test.expectedTestData.StringData, got.StringData)
		}
	}
}
