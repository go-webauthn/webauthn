//go:build go1.27

package webauthn

import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// CredentialParametersPQCRecommendedL3 returns the post-quantum credential algorithm list: ML-DSA-44, ML-DSA-65 and
// ML-DSA-87, followed by the Level 3 recommended algorithms EdDSA, ES256 and RS256. The order indicates preference,
// so an authenticator which implements a post-quantum algorithm produces a credential using one.
//
// The classical algorithms follow rather than being omitted because no authenticator in general use implements
// ML-DSA yet. A list naming the post-quantum algorithms alone would fail every registration until such an
// authenticator reaches the user's hands, which makes this the list to migrate with rather than the list to
// enforce a post-quantum policy with. A Relying Party which does want to enforce one names the ML-DSA identifiers
// on their own.
//
// The FIDO Alliance lists all three parameter sets as Recommended for servers.
//
// Specification: Server Requirements (WebAuthn Level 3 and CTAP 2.3) (https://fidoalliance.org/specs/fidoserver/fido-server-v2.3-rd-20260226.html)
func CredentialParametersPQCRecommendedL3() []protocol.CredentialParameter {
	return []protocol.CredentialParameter{
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgMLDSA44,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgMLDSA65,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgMLDSA87,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgEdDSA,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES256,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS256,
		},
	}
}
