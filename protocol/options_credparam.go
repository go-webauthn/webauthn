package protocol

import "github.com/go-webauthn/webauthn/protocol/webauthncose"

//go:generate msgp
//msgp:replace CredentialType with:string
//msgp:replace webauthncose.COSEAlgorithmIdentifier with:int

// CredentialParameter is the credential type and algorithm
// that the relying party wants the authenticator to create.
type CredentialParameter struct {
	Type      CredentialType                       `json:"type" msg:"type"`
	Algorithm webauthncose.COSEAlgorithmIdentifier `json:"alg" msg:"alg"`
}
