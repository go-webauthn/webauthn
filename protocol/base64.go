package protocol

import (
	"bytes"
	"encoding/base64"
	"reflect"
)

// URLEncodedBase64 represents a byte slice holding URL-encoded base64 data.
// When fields of this type are unmarshalled from JSON, the data is base64
// decoded into a byte slice.
type URLEncodedBase64 []byte

func (e URLEncodedBase64) String() string {
	return base64.RawURLEncoding.Strict().EncodeToString(e)
}

// UnmarshalJSON base64 decodes a URL-encoded value, storing the result in the
// provided byte slice.
func (e *URLEncodedBase64) UnmarshalJSON(data []byte) error {
	if bytes.Equal(data, []byte("null")) {
		return nil
	}

	// Trim the leading and trailing JSON encoding characters.
	data = bytes.Trim(data, `"`)

	// Trim the trailing padding characters.
	data = bytes.TrimRight(data, "=")

	encoding := base64.RawURLEncoding.Strict()

	out := make([]byte, encoding.DecodedLen(len(data)))

	n, err := encoding.Decode(out, data)
	if err != nil {
		return err
	}

	v := reflect.ValueOf(e).Elem()
	v.SetBytes(out[:n])

	return nil
}

// MarshalJSON base64 encodes a non URL-encoded value, storing the result in the
// provided byte slice.
func (e URLEncodedBase64) MarshalJSON() ([]byte, error) {
	if e == nil {
		return []byte("null"), nil
	}

	return []byte(`"` + e.String() + `"`), nil
}
