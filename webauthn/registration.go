package webauthn

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// BEGIN REGISTRATION
// These objects help us create the CredentialCreationOptions
// that will be passed to the authenticator via the user client

// RegistrationOption describes functions which are used to customize a registration request.
type RegistrationOption func(*protocol.PublicKeyCredentialCreationOptions)

// BeginRegistration generates a new set of registration data to be sent to the client and authenticator.
func (webauthn *WebAuthn) BeginRegistration(user User, opts ...RegistrationOption) (response *protocol.CredentialCreation, sessionData *SessionData, err error) {
	if err = webauthn.Config.validate(); err != nil {
		return nil, nil, fmt.Errorf("error occurred validating the configuration: %w", err)
	}

	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, nil, err
	}

	webAuthnUser := protocol.UserEntity{
		ID:          user.WebAuthnID(),
		DisplayName: user.WebAuthnDisplayName(),
		CredentialEntity: protocol.CredentialEntity{
			Name: user.WebAuthnName(),
			Icon: user.WebAuthnIcon(),
		},
	}

	relyingParty := protocol.RelyingPartyEntity{
		ID: webauthn.Config.RPID,
		CredentialEntity: protocol.CredentialEntity{
			Name: webauthn.Config.RPDisplayName,
			Icon: webauthn.Config.RPIcon,
		},
	}

	credentialParams := defaultRegistrationCredentialParameters()

	creationOptions := protocol.PublicKeyCredentialCreationOptions{
		Challenge:              challenge,
		RelyingParty:           relyingParty,
		User:                   webAuthnUser,
		Parameters:             credentialParams,
		AuthenticatorSelection: webauthn.Config.AuthenticatorSelection,
		Attestation:            webauthn.Config.AttestationPreference,
	}

	for _, setter := range opts {
		setter(&creationOptions)
	}

	if creationOptions.Timeout == 0 {
		switch {
		case creationOptions.AuthenticatorSelection.UserVerification == protocol.VerificationDiscouraged:
			creationOptions.Timeout = int(webauthn.Config.Timeouts.Registration.Timeout.Milliseconds())
		default:
			creationOptions.Timeout = int(webauthn.Config.Timeouts.Registration.Timeout.Milliseconds())
		}
	}

	sessionData = &SessionData{
		Challenge:        challenge.String(),
		UserID:           user.WebAuthnID(),
		UserVerification: creationOptions.AuthenticatorSelection.UserVerification,
	}

	if webauthn.Config.Timeouts.Registration.Enforce {
		sessionData.Expires = time.Now().Add(time.Millisecond * time.Duration(creationOptions.Timeout))
	}

	return &protocol.CredentialCreation{Response: creationOptions}, sessionData, nil
}

// WithAuthenticatorSelection is a RegistrationOption which allows provision of non-default parameters regarding the
// authenticator to select.
func WithAuthenticatorSelection(authenticatorSelection protocol.AuthenticatorSelection) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection = authenticatorSelection
	}
}

// WithExclusions is a RegistrationOption which allows provision of non-default parameters regarding credentials to
// exclude from retrieval.
func WithExclusions(excludeList []protocol.CredentialDescriptor) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.CredentialExcludeList = excludeList
	}
}

// WithConveyancePreference is a RegistrationOption which allows provision of non-default parameters regarding whether
// the authenticator should attest to the credential.
func WithConveyancePreference(preference protocol.ConveyancePreference) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Attestation = preference
	}
}

// WithExtensions is a RegistrationOption which allows provision of non-default extensions.
func WithExtensions(extension protocol.AuthenticationExtensions) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Extensions = extension
	}
}

// WithCredentialParameters is a RegistrationOption which allows provision of non-default parameters regarding the
// protocol credential parameters.
func WithCredentialParameters(credentialParams []protocol.CredentialParameter) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.Parameters = credentialParams
	}
}

// WithAppIdExcludeExtension automatically includes the specified appid if the CredentialExcludeList contains a credential
// with the type `fido-u2f`.
func WithAppIdExcludeExtension(appid string) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		for _, credential := range cco.CredentialExcludeList {
			if credential.AttestationType == protocol.CredentialTypeFIDOU2F {
				if cco.Extensions == nil {
					cco.Extensions = map[string]interface{}{}
				}

				cco.Extensions[protocol.ExtensionAppIDExclude] = appid
			}
		}
	}
}

// WithResidentKeyRequirement sets both the resident key and require resident key protocol options. When
func WithResidentKeyRequirement(requirement protocol.ResidentKeyRequirement) RegistrationOption {
	return func(cco *protocol.PublicKeyCredentialCreationOptions) {
		cco.AuthenticatorSelection.ResidentKey = requirement

		switch requirement {
		case protocol.ResidentKeyRequirementRequired:
			cco.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyRequired()
		default:
			cco.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyNotRequired()
		}
	}
}

// FinishRegistration takes the response from the authenticator and client and verify the credential against the user's
// credentials and session data.
func (webauthn *WebAuthn) FinishRegistration(user User, session SessionData, response *http.Request) (*Credential, error) {
	parsedResponse, err := protocol.ParseCredentialCreationResponse(response)
	if err != nil {
		return nil, err
	}

	return webauthn.CreateCredential(user, session, parsedResponse)
}

// CreateCredential verifies a parsed response against the user's credentials and session data.
func (webauthn *WebAuthn) CreateCredential(user User, session SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (*Credential, error) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		return nil, protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	if !session.Expires.IsZero() && session.Expires.Before(time.Now()) {
		return nil, protocol.ErrBadRequest.WithDetails("Session has Expired")
	}

	shouldVerifyUser := session.UserVerification == protocol.VerificationRequired

	invalidErr := parsedResponse.Verify(session.Challenge, shouldVerifyUser, webauthn.Config.RPID, webauthn.Config.RPOrigins)
	if invalidErr != nil {
		return nil, invalidErr
	}

	return MakeNewCredential(parsedResponse)
}

func defaultRegistrationCredentialParameters() []protocol.CredentialParameter {
	return []protocol.CredentialParameter{
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES256,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES384,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgES512,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS256,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS384,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgRS512,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS256,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS384,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgPS512,
		},
		{
			Type:      protocol.PublicKeyCredentialType,
			Algorithm: webauthncose.AlgEdDSA,
		},
	}
}
