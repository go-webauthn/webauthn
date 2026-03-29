package webauthn

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestNewCredentialFlags(t *testing.T) {
	testCases := []struct {
		name                   string
		flags                  protocol.AuthenticatorFlags
		expectedUserPresent    bool
		expectedUserVerified   bool
		expectedBackupEligible bool
		expectedBackupState    bool
	}{
		{
			name:                   "ShouldHandleNoFlags",
			flags:                  0,
			expectedUserPresent:    false,
			expectedUserVerified:   false,
			expectedBackupEligible: false,
			expectedBackupState:    false,
		},
		{
			name:                   "ShouldHandleAllFlags",
			flags:                  protocol.FlagUserPresent | protocol.FlagUserVerified | protocol.FlagBackupEligible | protocol.FlagBackupState,
			expectedUserPresent:    true,
			expectedUserVerified:   true,
			expectedBackupEligible: true,
			expectedBackupState:    true,
		},
		{
			name:                   "ShouldHandleUserPresentOnly",
			flags:                  protocol.FlagUserPresent,
			expectedUserPresent:    true,
			expectedUserVerified:   false,
			expectedBackupEligible: false,
			expectedBackupState:    false,
		},
		{
			name:                   "ShouldHandleBackupFlags",
			flags:                  protocol.FlagBackupEligible | protocol.FlagBackupState,
			expectedUserPresent:    false,
			expectedUserVerified:   false,
			expectedBackupEligible: true,
			expectedBackupState:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result := NewCredentialFlags(tc.flags)

			assert.Equal(t, tc.expectedUserPresent, result.UserPresent)
			assert.Equal(t, tc.expectedUserVerified, result.UserVerified)
			assert.Equal(t, tc.expectedBackupEligible, result.BackupEligible)
			assert.Equal(t, tc.expectedBackupState, result.BackupState)
			assert.Equal(t, tc.flags, result.ProtocolValue())
		})
	}
}

func TestCredential_Verify(t *testing.T) {
	testCases := []struct {
		name string
		have Credential
		err  string
	}{
		{
			name: "ShouldFailNilProvider",
			have: Credential{},
			err:  "error verifying credential: the metadata provider must be provided but it's nil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.have.Verify(nil)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestNewCredential(t *testing.T) {
	testCases := []struct {
		name           string
		clientDataHash []byte
		parsed         *protocol.ParsedCredentialCreationData
		expected       *Credential
	}{
		{
			name:           "ShouldCreateCredential",
			clientDataHash: []byte("client-data-hash"),
			parsed: &protocol.ParsedCredentialCreationData{
				ParsedPublicKeyCredential: protocol.ParsedPublicKeyCredential{
					AuthenticatorAttachment: protocol.Platform,
				},
				Response: protocol.ParsedAttestationResponse{
					AttestationObject: protocol.AttestationObject{
						Format: "packed",
						AuthData: protocol.AuthenticatorData{
							Counter: 1,
							Flags:   protocol.FlagUserPresent | protocol.FlagUserVerified,
							AttData: protocol.AttestedCredentialData{
								AAGUID:              []byte("aaguid-value-here"),
								CredentialID:        []byte("credential-id"),
								CredentialPublicKey: []byte("public-key"),
							},
						},
					},
					Transports: []protocol.AuthenticatorTransport{protocol.USB},
				},
				Raw: protocol.CredentialCreationResponse{
					AttestationResponse: protocol.AuthenticatorAttestationResponse{
						AuthenticatorResponse: protocol.AuthenticatorResponse{
							ClientDataJSON: []byte("client-data-json"),
						},
						AuthenticatorData:  []byte("auth-data"),
						PublicKeyAlgorithm: -7,
						AttestationObject:  []byte("attestation-object"),
					},
				},
			},
			expected: &Credential{
				ID:              []byte("credential-id"),
				PublicKey:       []byte("public-key"),
				AttestationType: "packed",
				Transport:       []protocol.AuthenticatorTransport{protocol.USB},
				Flags:           NewCredentialFlags(protocol.FlagUserPresent | protocol.FlagUserVerified),
				Authenticator: Authenticator{
					AAGUID:     []byte("aaguid-value-here"),
					SignCount:  1,
					Attachment: protocol.Platform,
				},
				Attestation: CredentialAttestation{
					ClientDataJSON:     []byte("client-data-json"),
					ClientDataHash:     []byte("client-data-hash"),
					AuthenticatorData:  []byte("auth-data"),
					PublicKeyAlgorithm: -7,
					Object:             []byte("attestation-object"),
				},
			},
		},
		{
			name:           "ShouldCreateCredentialWithNilHash",
			clientDataHash: nil,
			parsed: &protocol.ParsedCredentialCreationData{
				Response: protocol.ParsedAttestationResponse{
					AttestationObject: protocol.AttestationObject{
						Format: "none",
						AuthData: protocol.AuthenticatorData{
							AttData: protocol.AttestedCredentialData{
								CredentialID:        []byte("cred-2"),
								CredentialPublicKey: []byte("pub-2"),
							},
						},
					},
				},
				Raw: protocol.CredentialCreationResponse{},
			},
			expected: &Credential{
				ID:              []byte("cred-2"),
				PublicKey:       []byte("pub-2"),
				AttestationType: "none",
				Flags:           CredentialFlags{},
				Authenticator:   Authenticator{},
				Attestation:     CredentialAttestation{},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, err := NewCredential(tc.clientDataHash, tc.parsed)
			require.NoError(t, err)
			assert.Equal(t, tc.expected, actual)
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
