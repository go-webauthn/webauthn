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

func TestUnmarshalFirstAcceptsTrailingData(t *testing.T) {
	var decoded map[string]any

	n, err := UnmarshalFirst(append(append([]byte{}, item...), item...), &decoded)

	require.NoError(t, err)
	assert.Equal(t, len(item), n)
	assert.Equal(t, map[string]any{"a": uint64(1)}, decoded)
}
