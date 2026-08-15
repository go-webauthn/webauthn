package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSignalAllAcceptedCredentials(t *testing.T) {
	testCases := []struct {
		name         string
		rpid         string
		have         AllAcceptedCredentialsUser
		expected     *SignalAllAcceptedCredentials
		expectedJSON string
	}{
		{
			"ShouldHandleNil",
			"example.com",
			nil,
			nil,
			"null",
		},
		{
			"ShouldHandleStandard",
			"example.com",
			&signalUser{
				id:          []byte("123"),
				credentials: [][]byte{[]byte("456"), []byte("123")},
			},
			&SignalAllAcceptedCredentials{
				AllAcceptedCredentialIDs: []URLEncodedBase64{[]byte("456"), []byte("123")},
				RPID:                     "example.com",
				UserID:                   []byte("123"),
			},
			`{"allAcceptedCredentialIds":["NDU2","MTIz"],"rpId":"example.com","userId":"MTIz"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewSignalAllAcceptedCredentials(tc.rpid, tc.have)

			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}

func TestNewSignalCurrentUserDetails(t *testing.T) {
	testCases := []struct {
		name         string
		rpid         string
		have         CurrentUserDetailsUser
		expected     *SignalCurrentUserDetails
		expectedJSON string
	}{
		{
			"ShouldHandleNil",
			"example.com",
			nil,
			nil,
			"null",
		},
		{
			"ShouldHandleStandard",
			"example.com",
			&signalUser{
				id:          []byte("123"),
				name:        "alex",
				displayName: "Alex Müller",
			},
			&SignalCurrentUserDetails{
				DisplayName: "Alex Müller",
				Name:        "alex",
				RPID:        "example.com",
				UserID:      []byte("123"),
			},
			`{"displayName":"Alex Müller","name":"alex","rpId":"example.com","userId":"MTIz"}`,
		},
		{
			"ShouldHandleEmptyDetails",
			"example.com",
			&signalUser{
				id: []byte("123"),
			},
			&SignalCurrentUserDetails{
				RPID:   "example.com",
				UserID: []byte("123"),
			},
			`{"displayName":"","name":"","rpId":"example.com","userId":"MTIz"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := NewSignalCurrentUserDetails(tc.rpid, tc.have)

			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}

type signalUser struct {
	id          []byte
	credentials [][]byte
	name        string
	displayName string
}

func (u *signalUser) WebAuthnID() []byte {
	return u.id
}

func (u *signalUser) WebAuthnCredentialIDs() [][]byte {
	return u.credentials
}

func (u *signalUser) WebAuthnName() string {
	return u.name
}

func (u *signalUser) WebAuthnDisplayName() string {
	return u.displayName
}
