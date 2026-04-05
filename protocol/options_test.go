package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestPublicKeyCredentialRequestOptions_GetAllowedCredentialIDs(t *testing.T) {
	type fields struct {
		Challenge          URLEncodedBase64
		Timeout            int
		RelyingPartyID     string
		AllowedCredentials []CredentialDescriptor
		UserVerification   UserVerificationRequirement
		Extensions         AuthenticationExtensions
	}

	testCases := []struct {
		name     string
		fields   fields
		expected [][]byte
	}{
		{
			"CorrectCredentialIDs",
			fields{
				Challenge: URLEncodedBase64([]byte{0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00}),
				Timeout:   60,
				AllowedCredentials: []CredentialDescriptor{
					{
						Type: PublicKeyCredentialType, CredentialID: []byte("1234"), Transport: []AuthenticatorTransport{"usb"},
					},
				},
				RelyingPartyID:   "test.org",
				UserVerification: VerificationPreferred,
				Extensions:       AuthenticationExtensions{},
			},
			[][]byte{
				[]byte("1234"),
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			options := &PublicKeyCredentialRequestOptions{
				Challenge:          tc.fields.Challenge,
				Timeout:            tc.fields.Timeout,
				RelyingPartyID:     tc.fields.RelyingPartyID,
				AllowedCredentials: tc.fields.AllowedCredentials,
				UserVerification:   tc.fields.UserVerification,
				Extensions:         tc.fields.Extensions,
			}

			assert.Equal(t, tc.expected, options.GetAllowedCredentialIDs())
		})
	}
}

func TestCredentialDescriptor_SignalUnknownCredential(t *testing.T) {
	testCases := []struct {
		name         string
		rpid         string
		have         *CredentialDescriptor
		expected     *SignalUnknownCredential
		expectedJSON string
	}{
		{
			"ShouldHandleStandard",
			"example.com",
			&CredentialDescriptor{
				CredentialID: URLEncodedBase64("1234"),
			},
			&SignalUnknownCredential{
				CredentialID: URLEncodedBase64("1234"),
				RPID:         "example.com",
			},
			`{"credentialId":"MTIzNA","rpId":"example.com"}`,
		},
		{
			"ShouldHandleNoID",
			"example.com",
			&CredentialDescriptor{},
			&SignalUnknownCredential{
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
