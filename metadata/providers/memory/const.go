package memory

import "github.com/go-webauthn/webauthn/metadata"

// defaultUndesiredAuthenticatorStatus is an array of undesirable authenticator statuses
var defaultUndesiredAuthenticatorStatus = [...]metadata.AuthenticatorStatus{
	metadata.AttestationKeyCompromise,
	metadata.UserVerificationBypass,
	metadata.UserKeyRemoteCompromise,
	metadata.UserKeyPhysicalCompromise,
	metadata.Revoked,
}
