package webauthn

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestMakeNewCredential(t *testing.T) {
	type args struct {
		c *protocol.ParsedCredentialCreationData
	}

	var testCases []struct {
		name     string
		args     args
		expected *Credential
		err      string
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NewCredential(nil, tc.args.c)
			if len(tc.err) > 0 {
				assert.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)

				assert.EqualValues(t, tc.expected, actual)
			}
		})
	}
}

func TestCredential_SignalUnknownCredential(t *testing.T) {
	testCases := []struct {
		name         string
		rpid         string
		have         *Credential
		expected     *protocol.SignalUnknownCredential
		expectedJSON string
	}{
		{
			"ShouldHandleStandard",
			"example.com",
			&Credential{
				ID: []byte("1234"),
			},
			&protocol.SignalUnknownCredential{
				CredentialID: protocol.URLEncodedBase64("1234"),
				RPID:         "example.com",
			},
			`{"credentialId":"MTIzNA","rpId":"example.com"}`,
		},
		{
			"ShouldHandleNoID",
			"example.com",
			&Credential{},
			&protocol.SignalUnknownCredential{
				RPID: "example.com",
			},
			`{"credentialId":null,"rpId":"example.com"}`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.SignalUnknownCredential(tc.rpid)

			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}

func TestCredentials_CredentialDescriptors(t *testing.T) {
	testCases := []struct {
		name         string
		have         Credentials
		expected     []protocol.CredentialDescriptor
		expectedJSON string
	}{
		{
			"ShouldHandleStandard",
			Credentials{
				Credential{
					ID: []byte("1234"),
				},
			},
			[]protocol.CredentialDescriptor{
				{
					Type:         protocol.PublicKeyCredentialType,
					CredentialID: protocol.URLEncodedBase64("1234"),
				},
			},
			`[{"type":"public-key","id":"MTIzNA"}]`,
		},
		{
			"ShouldHandleEmpty",
			Credentials{},
			[]protocol.CredentialDescriptor{},
			`[]`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := tc.have.CredentialDescriptors()

			assert.Equal(t, tc.expected, actual)

			data, err := json.Marshal(actual)
			require.NoError(t, err)

			assert.Equal(t, tc.expectedJSON, string(data))
		})
	}
}
