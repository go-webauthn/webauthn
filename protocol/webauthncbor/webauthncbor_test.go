package webauthncbor

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var item = []byte{0xa1, 0x61, 0x61, 0x01}

func TestUnmarshalRejectsTrailingData(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
		err  string
	}{
		{
			name: "ShouldAcceptExactlyOneItem",
			data: item,
		},
		{
			name: "ShouldRejectTrailingItem",
			data: append(append([]byte{}, item...), item...),
			err:  "cbor: 4 bytes of extraneous data starting at index 4",
		},
		{
			name: "ShouldRejectTrailingByte",
			data: append(append([]byte{}, item...), 0x01),
			err:  "cbor: 1 bytes of extraneous data starting at index 4",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var decoded map[string]any

			err := Unmarshal(tc.data, &decoded)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				return
			}

			require.NoError(t, err)
			assert.Equal(t, map[string]any{"a": uint64(1)}, decoded)
		})
	}
}

func TestUnmarshalRequiresShortestForm(t *testing.T) {
	testCases := []struct {
		name string
		data []byte
		err  string
	}{
		{"ShouldAcceptUnsignedInHead", []byte{0x17}, ""},
		{"ShouldAcceptUnsignedInOneByte", []byte{0x18, 0x18}, ""},
		{"ShouldAcceptUnsignedInTwoBytes", []byte{0x19, 0x01, 0x00}, ""},
		{"ShouldAcceptUnsignedInFourBytes", []byte{0x1a, 0x00, 0x01, 0x00, 0x00}, ""},
		{"ShouldAcceptUnsignedInEightBytes", []byte{0x1b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00}, ""},
		{"ShouldAcceptNegativeInOneByte", []byte{0x38, 0x18}, ""},
		{"ShouldAcceptByteStringLengthInOneByte", append([]byte{0x58, 0x18}, make([]byte, 24)...), ""},
		{"ShouldAcceptFloatOfAnyWidth", []byte{0x83, 0xf9, 0x00, 0x00, 0xfa, 0x00, 0x00, 0x00, 0x00, 0xfb, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}, ""},
		{"ShouldAcceptSimpleValues", []byte{0x83, 0xf4, 0xf5, 0xf6}, ""},
		{"ShouldAcceptUnsortedMapKeys", []byte{0xa2, 0x61, 0x62, 0x01, 0x61, 0x61, 0x02}, ""},
		{"ShouldRejectUnsignedInOneByte", []byte{0x18, 0x17}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectUnsignedInTwoBytes", []byte{0x19, 0x00, 0xff}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectUnsignedInFourBytes", []byte{0x1a, 0x00, 0x00, 0xff, 0xff}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectUnsignedInEightBytes", []byte{0x1b, 0x00, 0x00, 0x00, 0x00, 0xff, 0xff, 0xff, 0xff}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectNegativeInOneByte", []byte{0x38, 0x06}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectByteStringLength", []byte{0x58, 0x01, 0x00}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectTextStringLength", []byte{0x78, 0x01, 0x61}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectArrayLength", []byte{0x98, 0x01, 0x01}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectMapLength", []byte{0xb8, 0x01, 0x61, 0x61, 0x01}, "cbor: integer or length at index 0 is not encoded in the fewest bytes possible"},
		{"ShouldRejectMapKey", []byte{0xa1, 0x18, 0x01, 0x01}, "cbor: integer or length at index 1 is not encoded in the fewest bytes possible"},
		{"ShouldRejectMapValue", []byte{0xa1, 0x61, 0x61, 0x18, 0x01}, "cbor: integer or length at index 3 is not encoded in the fewest bytes possible"},
		{"ShouldRejectNestedArrayElement", []byte{0xa1, 0x61, 0x61, 0x82, 0x01, 0x58, 0x01, 0x00}, "cbor: integer or length at index 5 is not encoded in the fewest bytes possible"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			var decoded any

			err := Unmarshal(tc.data, &decoded)

			var first any

			n, ferr := UnmarshalFirst(append(append([]byte{}, tc.data...), 0x18, 0x01), &first)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
				assert.EqualError(t, ferr, tc.err)
				assert.Zero(t, n)

				return
			}

			assert.NoError(t, err)
			assert.NoError(t, ferr)
			assert.Equal(t, len(tc.data), n)
			assert.Equal(t, decoded, first)
		})
	}
}

func TestIsByteString(t *testing.T) {
	testCases := []struct {
		name     string
		item     RawMessage
		expected bool
	}{
		{"ShouldAcceptByteString", RawMessage{0x41, 0x01}, true},
		{"ShouldAcceptEmptyByteString", RawMessage{0x40}, true},
		{"ShouldAcceptByteStringWithLengthInOneByte", append(RawMessage{0x58, 0x18}, make([]byte, 24)...), true},
		{"ShouldRejectArray", RawMessage{0x81, 0x01}, false},
		{"ShouldRejectTextString", RawMessage{0x61, 0x61}, false},
		{"ShouldRejectUnsigned", RawMessage{0x01}, false},
		{"ShouldRejectNull", RawMessage{0xf6}, false},
		{"ShouldRejectEmpty", RawMessage{}, false},
		{"ShouldRejectNil", nil, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsByteString(tc.item))
		})
	}
}

func TestUnmarshalFirstAcceptsTrailingData(t *testing.T) {
	var decoded map[string]any

	n, err := UnmarshalFirst(append(append([]byte{}, item...), item...), &decoded)

	require.NoError(t, err)
	assert.Equal(t, len(item), n)
	assert.Equal(t, map[string]any{"a": uint64(1)}, decoded)
}
