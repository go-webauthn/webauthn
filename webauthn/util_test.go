package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestIsByteArrayInSlice(t *testing.T) {
	testCases := []struct {
		name     string
		have     []byte
		haystack [][]byte
		expected bool
	}{
		{
			"ShouldMatchSingleEntry",
			[]byte("123"),
			[][]byte{[]byte("123")},
			true,
		},
		{
			"ShouldMatchMultiEntry",
			[]byte("123"),
			[][]byte{[]byte("bac"), []byte("123")},
			true,
		},
		{
			"ShouldNotMatchEmpty",
			[]byte("123"),
			nil,
			false,
		},
		{
			"ShouldNotMatchNotInSlice",
			[]byte("123"),
			[][]byte{[]byte("bac"), []byte("no")},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isByteArrayInSlice(tc.have, tc.haystack...))
		})
	}
}

func TestIsCredentialsAllowedMatchingOwned(t *testing.T) {
	testCases := []struct {
		name        string
		allowed     [][]byte
		credentials []Credential
		expected    bool
	}{
		{
			"ShouldMatchSingleEntry",
			[][]byte{[]byte("123")},
			[]Credential{
				{
					ID: []byte("123"),
				},
			},
			true,
		},
		{
			"ShouldMatchMultipleEntry",
			[][]byte{[]byte("123")},
			[]Credential{
				{
					ID: []byte("123"),
				},
				{
					ID: []byte("ab"),
				},
			},
			true,
		},
		{
			"ShouldMatchMultipleEntryAlt",
			[][]byte{[]byte("123"), []byte("ab")},
			[]Credential{
				{
					ID: []byte("123"),
				},
				{
					ID: []byte("ab"),
				},
			},
			true,
		},
		{
			"ShouldNotMatchDifferentCredentials",
			[][]byte{[]byte("123")},
			[]Credential{
				{
					ID: []byte("456"),
				},
			},
			false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, isCredentialsAllowedMatchingOwned(tc.allowed, tc.credentials))
		})
	}
}

func TestValidateSessionChallenge(t *testing.T) {
	testCases := []struct {
		name string
		have string
		err  string
	}{
		{
			"ShouldPassMinimumLength",
			"AAAAAAAAAAAAAAAAAAAAAA",
			"",
		},
		{
			"ShouldPassDefaultLength",
			"E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k",
			"",
		},
		{
			"ShouldFailEmpty",
			"",
			"The challenge must be at least 16 bytes but it has a length of 0",
		},
		{
			"ShouldFailShort",
			"AAAAAAAAAAAAAAAAAAAA",
			"The challenge must be at least 16 bytes but it has a length of 15",
		},
		{
			"ShouldFailPadded",
			"AAAAAAAAAAAAAAAAAAAAAA==",
			"The challenge could not be decoded: illegal base64 data at input byte 22",
		},
		{
			"ShouldFailStandardEncoding",
			"E4PTcIH/HfX1pC6Sigk1SC9NAlgeztN0439vi8z+c9k",
			"The challenge could not be decoded: illegal base64 data at input byte 7",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateSessionChallenge(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)

				return
			}

			var e *protocol.Error

			require.ErrorAs(t, err, &e)
			assert.Equal(t, protocol.ErrBadRequest.Type, e.Type)
			assert.Equal(t, "Session has an invalid challenge", e.Details)
			assert.Equal(t, tc.err, e.DevInfo)
		})
	}
}
