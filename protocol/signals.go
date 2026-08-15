package protocol

// NewSignalAllAcceptedCredentials creates a new SignalAllAcceptedCredentials struct that can simply be encoded with
// json.Marshal.
func NewSignalAllAcceptedCredentials(rpid string, user AllAcceptedCredentialsUser) *SignalAllAcceptedCredentials {
	if user == nil {
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
func NewSignalCurrentUserDetails(rpid string, user CurrentUserDetailsUser) *SignalCurrentUserDetails {
	if user == nil {
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
