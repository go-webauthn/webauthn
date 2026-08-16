package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"reflect"
	"strings"
)

// URLEncodedBase64 represents a byte slice holding URL-encoded base64 data.
// When fields of this type are unmarshalled from JSON, the data is base64
// decoded into a byte slice.
type URLEncodedBase64 []byte

func (e URLEncodedBase64) String() string {
	return base64.RawURLEncoding.EncodeToString(e)
}

// UnmarshalJSON base64 decodes a URL-encoded value, storing the result in the
// provided byte slice.
func (e *URLEncodedBase64) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}

	// A JSON value which is not a string is not base64 at all. Without this check the quote trimming below is a no-op
	// and the value itself is decoded, so a number or a boolean produces silent garbage bytes rather than an error.
	if len(data) < 2 || data[0] != '"' || data[len(data)-1] != '"' {
		return errBase64NotJSONString
	}

	// Decode the JSON string itself rather than reading the raw text between the quotes, so a value spelled with
	// JSON escapes decodes to the same bytes as the plain spelling. The base64url alphabet contains nothing which
	// has to be escaped, so such a value is unusual, but it is a legal encoding of one and the raw text is not.
	var value string

	if err := json.Unmarshal(data, &value); err != nil {
		return err
	}

	// Trim the trailing equal characters.
	value = strings.TrimRight(value, "=")

	out, err := base64.RawURLEncoding.DecodeString(value)
	if err != nil {
		return err
	}

	v := reflect.ValueOf(e).Elem()
	v.SetBytes(out)

	return nil
}

// MarshalJSON base64 encodes a non URL-encoded value, storing the result in the
// provided byte slice.
func (e URLEncodedBase64) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("null"), nil
	}

	return []byte(`"` + base64.RawURLEncoding.EncodeToString(e) + `"`), nil
}
