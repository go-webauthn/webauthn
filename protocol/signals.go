package protocol

import (
	"reflect"
)

func signalUserIsNil(user any) bool {
	if user == nil {
		return true
	}

	switch value := reflect.ValueOf(user); value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}

// NewSignalAllAcceptedCredentials creates a new SignalAllAcceptedCredentials struct that can simply be encoded with
// json.Marshal.
//
// A nil user, including a nil pointer carried in a non-nil interface, yields a nil result.
func NewSignalAllAcceptedCredentials(rpid string, user AllAcceptedCredentialsUser) *SignalAllAcceptedCredentials {
	if signalUserIsNil(user) {
		return nil
	}

	credentials := user.WebAuthnCredentialIDs()

	ids := make([]URLEncodedBase64, len(credentials))

	for i, id := range credentials {
		ids[i] = id
	}

	return &SignalAllAcceptedCredentials{
		AllAcceptedCredentialIDs: ids,
		RPID:                     rpid,
		UserID:                   user.WebAuthnID(),
	}
}

// SignalAllAcceptedCredentials is a struct which represents the CDDL of the same name.
type SignalAllAcceptedCredentials struct {
	AllAcceptedCredentialIDs []URLEncodedBase64 `json:"allAcceptedCredentialIds"`
	RPID                     string             `json:"rpId"`
	UserID                   URLEncodedBase64   `json:"userId"`
}

// NewSignalCurrentUserDetails creates a new SignalCurrentUserDetails struct that can simply be encoded with
// json.Marshal. It is the counterpart of [NewSignalAllAcceptedCredentials] for the signal a Relying Party sends
// after the name or display name of a user account changes.
//
// A [github.com/go-webauthn/webauthn/webauthn.User] satisfies [CurrentUserDetailsUser] as it stands, so the user
// value the ceremony methods already take can be passed straight through.
//
// A nil user, including a nil pointer carried in a non-nil interface, yields a nil result.
func NewSignalCurrentUserDetails(rpid string, user CurrentUserDetailsUser) *SignalCurrentUserDetails {
	if signalUserIsNil(user) {
		return nil
	}

	return &SignalCurrentUserDetails{
		DisplayName: user.WebAuthnDisplayName(),
		Name:        user.WebAuthnName(),
		RPID:        rpid,
		UserID:      user.WebAuthnID(),
	}
}

// SignalCurrentUserDetails is a struct which represents the CDDL of the same name.
type SignalCurrentUserDetails struct {
	DisplayName string           `json:"displayName"`
	Name        string           `json:"name"`
	RPID        string           `json:"rpId"`
	UserID      URLEncodedBase64 `json:"userId"`
}

// SignalUnknownCredential is a struct which represents the CDDL of the same name.
type SignalUnknownCredential struct {
	CredentialID URLEncodedBase64 `json:"credentialId"`
	RPID         string           `json:"rpId"`
}

// AllAcceptedCredentialsUser is an interface that can be implemented by a user to provide information about their
// accepted credentials.
type AllAcceptedCredentialsUser interface {
	WebAuthnID() []byte
	WebAuthnCredentialIDs() [][]byte
}

// CurrentUserDetailsUser is an interface that can be implemented by a user to provide the details a Relying Party
// signals after they change. It is a subset of [github.com/go-webauthn/webauthn/webauthn.User], which therefore
// satisfies it without any additional method.
type CurrentUserDetailsUser interface {
	WebAuthnID() []byte
	WebAuthnName() string
	WebAuthnDisplayName() string
}
