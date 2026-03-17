package webauthn

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

//go:generate msgp

//msgp:replace protocol.UserVerificationRequirement with:string
//msgp:replace protocol.AuthenticationExtensions with:map[string]any
//msgp:replace protocol.CredentialMediationRequirement with:string

// SessionData is the data that should be stored by the Relying Party for the duration of the web authentication
// ceremony.
type SessionData struct {
	Challenge            string    `json:"challenge" msg:"c"`
	RelyingPartyID       string    `json:"rpId" msg:"r"`
	UserID               []byte    `json:"user_id" msg:"u"`
	AllowedCredentialIDs [][]byte  `json:"allowed_credentials,omitempty" msg:"allow"`
	Expires              time.Time `json:"expires" msg:"exp"`

	UserVerification protocol.UserVerificationRequirement    `json:"userVerification" msg:"uv"`
	Extensions       protocol.AuthenticationExtensions       `json:"extensions,omitempty" msg:"exts"`
	CredParams       []protocol.CredentialParameter          `json:"credParams,omitempty" msg:"params"`
	Mediation        protocol.CredentialMediationRequirement `json:"mediation,omitempty" msg:"cmr"`
}
