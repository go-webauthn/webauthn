package webauthn

import (
	"bytes"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
)

// BEGIN REGISTRATION
// These objects help us creat the CredentialCreationOptions
// that will be passed to the authenticator via the user client

// LoginOption is used to provide parameters that modify the default Credential Assertion Payload that is sent to the user.
type LoginOption func(*protocol.PublicKeyCredentialRequestOptions)

// DiscoverableUserHandler returns a *User given the provided userHandle.
type DiscoverableUserHandler func(rawID, userHandle []byte) (user User, err error)

// Creates the CredentialAssertion data payload that should be sent to the user agent for beginning the
// login/assertion process. The format of this data can be seen in §5.5 of the WebAuthn specification
// (https://www.w3.org/TR/webauthn/#assertion-options). These default values can be amended by providing
// additional LoginOption parameters. This function also returns sessionData, that must be stored by the
// RP in a secure manner and then provided to the FinishLogin function. This data helps us verify the
// ownership of the credential being retreived.
func (webauthn *WebAuthn) BeginLogin(user User, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error) {
	credentials := user.WebAuthnCredentials()

	if len(credentials) == 0 { // If the user does not have any credentials, we cannot perform an assertion.
		return nil, nil, protocol.ErrBadRequest.WithDetails("Found no credentials for user")
	}

	var allowedCredentials = make([]protocol.CredentialDescriptor, len(credentials))

	for i, credential := range credentials {
		allowedCredentials[i] = credential.Descriptor()
	}

	return webauthn.beginLogin(user.WebAuthnID(), allowedCredentials, opts...)
}

// BeginDiscoverableLogin begins a client-side discoverable login, previously known as Resident Key logins.
func (webauthn *WebAuthn) BeginDiscoverableLogin(opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error) {
	return webauthn.beginLogin(nil, nil, opts...)
}

func (webauthn *WebAuthn) beginLogin(userID []byte, allowedCredentials []protocol.CredentialDescriptor, opts ...LoginOption) (*protocol.CredentialAssertion, *SessionData, error) {
	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, nil, err
	}

	requestOptions := protocol.PublicKeyCredentialRequestOptions{
		Challenge:          challenge,
		Timeout:            webauthn.Config.Timeout,
		RelyingPartyID:     webauthn.Config.RPID,
		UserVerification:   webauthn.Config.AuthenticatorSelection.UserVerification,
		AllowedCredentials: allowedCredentials,
	}

	for _, setter := range opts {
		setter(&requestOptions)
	}

	sessionData := SessionData{
		Challenge:            challenge.String(),
		UserID:               userID,
		AllowedCredentialIDs: requestOptions.GetAllowedCredentialIDs(),
		UserVerification:     requestOptions.UserVerification,
		Extensions:           requestOptions.Extensions,
	}

	response := protocol.CredentialAssertion{Response: requestOptions}

	return &response, &sessionData, nil
}

// Updates the allowed credential list with Credential Descripiptors, discussed in §5.10.3
// (https://www.w3.org/TR/webauthn/#dictdef-publickeycredentialdescriptor) with user-supplied values
func WithAllowedCredentials(allowList []protocol.CredentialDescriptor) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.AllowedCredentials = allowList
	}
}

// Request a user verification preference
func WithUserVerification(userVerification protocol.UserVerificationRequirement) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.UserVerification = userVerification
	}
}

// Request additional extensions for assertion
func WithAssertionExtensions(extensions protocol.AuthenticationExtensions) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		cco.Extensions = extensions
	}
}

// WithAppIdExtension automatically includes the specified appid if the AllowedCredentials contains a credential
// with the type `fido-u2f`.
func WithAppIdExtension(appid string) LoginOption {
	return func(cco *protocol.PublicKeyCredentialRequestOptions) {
		for _, credential := range cco.AllowedCredentials {
			if credential.AttestationType == protocol.CredentialTypeFIDOU2F {
				if cco.Extensions == nil {
					cco.Extensions = map[string]interface{}{}
				}

				cco.Extensions[protocol.ExtensionAppID] = appid
			}
		}
	}
}

// Take the response from the client and validate it against the user credentials and stored session data
func (webauthn *WebAuthn) FinishLogin(user User, session SessionData, response *http.Request) (*Credential, error) {
	parsedResponse, err := protocol.ParseCredentialRequestResponse(response)
	if err != nil {
		return nil, err
	}

	return webauthn.ValidateLogin(user, session, parsedResponse)
}

// ValidateLogin takes a parsed response and validates it against the user credentials and session data
func (webauthn *WebAuthn) ValidateLogin(user User, session SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*Credential, error) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		return nil, protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	return webauthn.validateLogin(user, session, parsedResponse)
}

// ValidateDiscoverableLogin is an overloaded version of ValidateLogin that allows for discoverable credentials.
func (webauthn *WebAuthn) ValidateDiscoverableLogin(handler DiscoverableUserHandler, session SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*Credential, error) {
	if session.UserID != nil {
		return nil, protocol.ErrBadRequest.WithDetails("Session was not initiated as a client-side discoverable login")
	}

	if parsedResponse.Response.UserHandle == nil {
		return nil, protocol.ErrBadRequest.WithDetails("Client-side Discoverable Assertion was attempted with a blank User Handle")
	}

	user, err := handler(parsedResponse.RawID, parsedResponse.Response.UserHandle)
	if err != nil {
		return nil, protocol.ErrBadRequest.WithDetails("Failed to lookup Client-side Discoverable Credential")
	}

	return webauthn.validateLogin(user, session, parsedResponse)
}

// ValidateLogin takes a parsed response and validates it against the user credentials and session data
func (webauthn *WebAuthn) validateLogin(user User, session SessionData, parsedResponse *protocol.ParsedCredentialAssertionData) (*Credential, error) {
	// Step 1. If the allowCredentials option was given when this authentication ceremony was initiated,
	// verify that credential.id identifies one of the public key credentials that were listed in
	// allowCredentials.

	// NON-NORMATIVE Prior Step: Verify that the allowCredentials for the session are owned by the user provided
	userCredentials := user.WebAuthnCredentials()
	var credentialFound bool
	if len(session.AllowedCredentialIDs) > 0 {
		var credentialsOwned bool
		for _, allowedCredentialID := range session.AllowedCredentialIDs {
			for _, userCredential := range userCredentials {
				if bytes.Equal(userCredential.ID, allowedCredentialID) {
					credentialsOwned = true
					break
				}
				credentialsOwned = false
			}
		}
		if !credentialsOwned {
			return nil, protocol.ErrBadRequest.WithDetails("User does not own all credentials from the allowedCredentialList")
		}
		for _, allowedCredentialID := range session.AllowedCredentialIDs {
			if bytes.Equal(parsedResponse.RawID, allowedCredentialID) {
				credentialFound = true
				break
			}
		}
		if !credentialFound {
			return nil, protocol.ErrBadRequest.WithDetails("User does not own the credential returned")
		}
	}

	// Step 2. If credential.response.userHandle is present, verify that the user identified by this value is
	// the owner of the public key credential identified by credential.id.

	// This is in part handled by our Step 1

	userHandle := parsedResponse.Response.UserHandle
	if len(userHandle) > 0 {
		if !bytes.Equal(userHandle, user.WebAuthnID()) {
			return nil, protocol.ErrBadRequest.WithDetails("userHandle and User ID do not match")
		}
	}

	// Step 3. Using credential’s id attribute (or the corresponding rawId, if base64url encoding is inappropriate
	// for your use case), look up the corresponding credential public key.
	var loginCredential Credential
	for _, cred := range userCredentials {
		if bytes.Equal(cred.ID, parsedResponse.RawID) {
			loginCredential = cred
			credentialFound = true
			break
		}
		credentialFound = false
	}

	if !credentialFound {
		return nil, protocol.ErrBadRequest.WithDetails("Unable to find the credential for the returned credential ID")
	}

	shouldVerifyUser := session.UserVerification == protocol.VerificationRequired

	rpID := webauthn.Config.RPID
	rpOrigin := webauthn.Config.RPOrigin

	appID, err := parsedResponse.GetAppID(session.Extensions, loginCredential.AttestationType)
	if err != nil {
		return nil, err
	}

	// Handle steps 4 through 16
	validError := parsedResponse.Verify(session.Challenge, rpID, rpOrigin, appID, shouldVerifyUser, loginCredential.PublicKey)
	if validError != nil {
		return nil, validError
	}

	// Handle step 17
	loginCredential.Authenticator.UpdateCounter(parsedResponse.Response.AuthenticatorData.Counter)

	return &loginCredential, nil
}
