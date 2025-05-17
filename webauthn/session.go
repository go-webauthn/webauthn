package webauthn

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

//go:generate msgp
//msgp:replace protocol.UserVerificationRequirement with:string
//msgp:replace protocol.AuthenticationExtensions with:map[string]any

// SessionData is the data that should be stored by the Relying Party for the duration of the web authentication
// ceremony.
type SessionData struct {
	Challenge            string    `json:"challenge" msg:"challenge"`
	RelyingPartyID       string    `json:"rpId" msg:"rpid"`
	UserID               []byte    `json:"user_id" msg:"uid"`
	AllowedCredentialIDs [][]byte  `json:"allowed_credentials,omitempty" msg:"allowed"`
	Expires              time.Time `json:"expires" msg:"exp"`

	UserVerification protocol.UserVerificationRequirement `json:"userVerification" msg:"uv"`
	Extensions       protocol.AuthenticationExtensions    `json:"extensions,omitempty" msg:"ext"`
	CredParams       []protocol.CredentialParameter       `json:"credParams,omitempty" msg:"params"`
}
