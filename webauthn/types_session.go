package webauthn

import (
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

//go:generate msgp -unexported

//msgp:replace protocol.UserVerificationRequirement with:string
//msgp:replace protocol.CredentialMediationRequirement with:string
//msgp:replace protocol.SessionExtensions with:sessionExtensions
//msgp:replace protocol.LargeBlobSupport with:string
//msgp:replace protocol.CredentialProtectionPolicy with:string
//msgp:clearomitted

// sessionExtensions shadows [protocol.SessionExtensions] for the msgp code generator, which cannot inspect types
// in other packages. It MUST stay field-for-field convertible with [protocol.SessionExtensions]; the conversion in
// the generated code fails to compile otherwise, and TestSessionExtensionsShadowMatches asserts it directly.
//
// The generator only visits unexported types when invoked with -unexported, hence the go:generate line above.
//
// The exts field of [SessionData] deliberately carries no omitempty tag option. msgp cannot test a replaced struct
// for emptiness, so the option never suppressed the field on the wire, while //msgp:clearomitted additionally
// emitted an assignment to the field's address which does not compile. Do not add it back (msgp v1.6.4).
// A msg tag MUST NOT exceed 17 characters. The generated EncodeMsg emits each map key as a single
// msgp.Writer.Append call carrying the one byte fixstr header plus the tag, and that method silently truncates a
// payload larger than the writer's buffer while still returning a nil error (msgp v1.6.4). The smallest buffer msgp
// will construct is 18 bytes, so 17 tag characters plus the header is the largest key that fits and a tag of 18
// characters or more corrupts the encoded session for any caller using msgp.NewWriterSize with a small size.
// TestSessionData_MsgpEncodeErrorPaths encodes through an 18 byte writer and fails if this is reintroduced.
type sessionExtensions struct {
	Requested                         []string                            `msg:"req,omitempty"`
	AppID                             string                              `msg:"appid,omitempty"`
	AppIDExclude                      string                              `msg:"appidExclude,omitempty"`
	LargeBlob                         protocol.LargeBlobSupport           `msg:"largeBlob,omitempty"`
	LargeBlobRead                     bool                                `msg:"lbRead,omitempty"`
	LargeBlobWrite                    bool                                `msg:"lbWrite,omitempty"`
	CredentialProtectionPolicy        protocol.CredentialProtectionPolicy `msg:"credProtect,omitempty"`
	EnforceCredentialProtectionPolicy bool                                `msg:"cpEnforce,omitempty"`
	CredBlob                          bool                                `msg:"credBlob,omitempty"`
	Extra                             map[string]any                      `msg:"extra,omitempty"`
}

// SessionData is the data that must be stored by the Relying Party between the Begin and Finish steps of a WebAuthn
// ceremony. It contains the challenge and other parameters needed to verify the authenticator's response.
//
// The Relying Party must store this data securely and associate it with the user's session. It should not be
// modifiable by the client (i.e. store it server-side or in a signed, opaque cookie). After the ceremony completes,
// the session data should be discarded.
//
// Every field returned by the Begin* functions must be delivered to the matching Finish* / Validate* call with
// the same values; if anything is dropped or reshaped in transit, verification will fail. Treat [SessionData] as
// an atomic record between those two calls.
//
// Decode into a fresh [SessionData]. Unlike the other members, Extensions is not reset when the encoded payload
// omits it, so decoding a payload that predates the field, or one written by a different producer, over a reused
// destination leaves the previous ceremony's extension state in place.
//
// For consolidated persistence guidance; recommended schema shape, required lookup columns, and the rules
// that also apply to [Credential] records; see the [Storage] section of the
// [github.com/go-webauthn/webauthn/webauthn] package documentation.
//
// [Storage]: https://pkg.go.dev/github.com/go-webauthn/webauthn/webauthn#hdr-Storage
type SessionData struct {
	Challenge            string    `json:"challenge" msg:"c"`
	RelyingPartyID       string    `json:"rpId,omitempty" msg:"r,omitempty"`
	Origin               string    `json:"origin,omitempty" msg:"o,omitempty"`
	UserID               []byte    `json:"user_id,omitempty" msg:"u,omitempty"`
	AllowedCredentialIDs [][]byte  `json:"allowed_credentials,omitempty" msg:"allow,omitempty"`
	Expires              time.Time `json:"expires" msg:"exp"`

	UserVerification protocol.UserVerificationRequirement    `json:"userVerification,omitempty" msg:"uv,omitempty"`
	Extensions       protocol.SessionExtensions              `json:"extensions,omitzero" msg:"exts"`
	CredParams       []protocol.CredentialParameter          `json:"credParams,omitempty" msg:"params,omitempty"`
	Mediation        protocol.CredentialMediationRequirement `json:"mediation,omitempty" msg:"cmr,omitempty"`
}

// GetRelyingPartyID returns the Relying Party ID the ceremony was begun with, which is the value the rpIdHash in the
// authenticator data must be verified against. The Begin* functions always record it, so it reflects any per-ceremony
// override applied by [WithRegistrationRelyingPartyID] or [WithLoginRelyingPartyID].
//
// The supplied fallback, which callers take from [Config.RPID], is returned when the session carries no Relying Party
// ID. That is the case for a session encoded before this member existed, and for one a caller constructed directly,
// neither of which can have used a per-ceremony override.
func (s SessionData) GetRelyingPartyID(fallback string) string {
	if len(s.RelyingPartyID) == 0 {
		return fallback
	}

	return s.RelyingPartyID
}

// GetOrigins returns the origins the collected client data of the ceremony response may declare. A ceremony begun with
// [WithRegistrationOrigin] or [WithLoginOrigin] is bound to exactly one of them, in which case only that origin is
// returned and a response collected at any other origin the Relying Party serves fails verification.
func (s SessionData) GetOrigins(fallback []string) []string {
	if len(s.Origin) == 0 {
		return fallback
	}

	return []string{s.Origin}
}
