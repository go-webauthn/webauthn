package protocol

import (
	"encoding/base64"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCreateChallenge(t *testing.T) {
	challenge, err := CreateChallenge()

	assert.NoError(t, err)
	require.NotNil(t, challenge)
	assert.Len(t, challenge, 32)
}

func TestChallenge_String(t *testing.T) {
	newChallenge, err := CreateChallenge()
	require.NoError(t, err)

	assert.NotNil(t, newChallenge)

	expectedChallenge := base64.RawURLEncoding.EncodeToString(newChallenge)

	testCases := []struct {
		name     string
		have     URLEncodedBase64
		expected string
	}{
		{
			"Successful",
			newChallenge,
			expectedChallenge,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.String())
		})
	}
}
