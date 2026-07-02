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

func TestValidateChainFallbackRoot(t *testing.T) {
	// When x5c is absent the caller sets chain = []any{root}. The single-entry
	// root chain must be accepted so that no-x5c MDS blobs can still be parsed.
	valid, err := validateChain(ConformanceMDSRoot, []any{ConformanceMDSRoot})

	assert.True(t, valid)
	assert.NoError(t, err)
}
