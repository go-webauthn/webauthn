package webauthn_test

import "github.com/go-webauthn/webauthn/webauthn"

type defaultUser struct {
	id          []byte
	credentials []webauthn.Credential
}

var _ webauthn.User = (*defaultUser)(nil)

func (user *defaultUser) WebAuthnID() []byte {
	return user.id
}

func (user *defaultUser) WebAuthnName() string {
	return "newUser"
}

func (user *defaultUser) WebAuthnDisplayName() string {
	return "New User"
}

func (user *defaultUser) WebAuthnCredentials() []webauthn.Credential {
	return user.credentials
}

func GetUser() *defaultUser {
	return &defaultUser{}
}
