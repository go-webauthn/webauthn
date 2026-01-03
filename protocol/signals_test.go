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

			data, err := json.Marshal(tc.expected)
			assert.NoError(t, err)
			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}

type signalUser struct {
	id          []byte
	credentials [][]byte
}

func (u *signalUser) WebAuthnID() []byte {
	return u.id
}

func (u *signalUser) WebAuthnCredentialIDs() [][]byte {
	return u.credentials
}
