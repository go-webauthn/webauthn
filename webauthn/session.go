package webauthn

import "github.com/go-webauthn/webauthn/protocol"

// SessionData is the data that should be stored by the Relying Party for the duration of the web authentication
// ceremony.
type SessionData struct {
	Challenge            string                               `json:"challenge"`
	UserID               []byte                               `json:"user_id"`
	UserDisplayName      string                               `json:"user_display_name"`
	AllowedCredentialIDs [][]byte                             `json:"allowed_credentials,omitempty"`
	UserVerification     protocol.UserVerificationRequirement `json:"userVerification"`
	Extensions           protocol.AuthenticationExtensions    `json:"extensions,omitempty"`
}
