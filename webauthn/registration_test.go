package webauthn

import (
	"encoding/json"
	"testing"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/stretchr/testify/assert"
)

func TestRegistration_FinishRegistrationFailure(t *testing.T) {
	user := &defaultUser{
		id: []byte("123"),
	}

	session := SessionData{
		UserID: []byte("ABC"),
	}

	webauthn := &WebAuthn{}

	credential, err := webauthn.FinishRegistration(user, session, nil)
	if err == nil {
		t.Errorf("FinishRegistration() error = nil, want %v", protocol.ErrBadRequest.Type)
	}

	if credential != nil {
		t.Errorf("FinishRegistration() credential = %v, want nil", credential)
	}
}

func TestEntityEncoding(t *testing.T) {
	testCases := []struct {
		name           string
		b64            bool
		have, expected string
	}{
		{"ShouldEncodeBase64", true, "abc", "{\"name\":\"\",\"id\":\"YWJj\"}"},
		{"ShouldEncodeString", false, "abc", "{\"name\":\"\",\"id\":\"abc\"}"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entityUser := protocol.UserEntity{}

			if tc.b64 {
				entityUser.ID = protocol.URLEncodedBase64(tc.have)
			} else {
				entityUser.ID = tc.have
			}

			data, err := json.Marshal(entityUser)

			assert.NoError(t, err)

			assert.Equal(t, tc.expected, string(data))
		})
	}
}
