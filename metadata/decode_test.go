package metadata

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateChainMalformed(t *testing.T) {
	testCases := []struct {
		name  string
		chain []any
	}{
		{
			name:  "ShouldHandleEmptyChain",
			chain: []any{},
		},
		{
			name:  "ShouldHandleSingleElementChain",
			chain: []any{"leaf"},
		},
		{
			name:  "ShouldHandleNonStringLeaf",
			chain: []any{1, "intermediate"},
		},
		{
			name:  "ShouldHandleNonStringIntermediate",
			chain: []any{"leaf", 2},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NotPanics(t, func() {
				valid, err := validateChain(ConformanceMDSRoot, tc.chain)

				assert.False(t, valid)
				assert.Equal(t, errInvalidCertificateChain, err)
			})
		})
	}
}
