package webauthn

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

//go:generate msgp

//msgp:replace protocol.UserVerificationRequirement with:string
//msgp:replace protocol.AuthenticationExtensions with:map[string]any
//msgp:replace protocol.CredentialMediationRequirement with:string

// SessionData is the data that must be stored by the Relying Party between the Begin and Finish steps of a WebAuthn
// ceremony. It contains the challenge and other parameters needed to verify the authenticator's response.
//
// The Relying Party must store this data securely and associate it with the user's session. It should not be
// modifiable by the client (e.g. store it server-side or in a signed, opaque cookie). After the ceremony completes,
// the session data should be discarded.
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
