package webauthn

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// RegistrationOption describes a function which modifies the registration
// [*protocol.PublicKeyCredentialCreationOptions] values.
type RegistrationOption func(*protocol.PublicKeyCredentialCreationOptions)

// BeginRegistration generates a new set of registration data to be sent to the client and authenticator. To set a
// conditional mediation requirement for the registration see [WebAuthn.BeginMediatedRegistration].
func (webauthn *WebAuthn) BeginRegistration(user User, opts ...RegistrationOption) (creation *protocol.CredentialCreation, session *SessionData, err error) {
	return webauthn.BeginMediatedRegistration(user, protocol.MediationDefault, opts...)
}

// BeginMediatedRegistration is similar to [WebAuthn.BeginRegistration] however it also allows specifying a credential
// mediation requirement.
func (webauthn *WebAuthn) BeginMediatedRegistration(user User, mediation protocol.CredentialMediationRequirement, opts ...RegistrationOption) (creation *protocol.CredentialCreation, session *SessionData, err error) {
	if err = webauthn.Config.validate(); err != nil {
		return nil, nil, fmt.Errorf(errFmtConfigValidate, err)
	}

	challenge, err := protocol.CreateChallenge()
	if err != nil {
		return nil, nil, err
	}

	var entityUserID any

	if webauthn.Config.EncodeUserIDAsString {
		entityUserID = string(user.WebAuthnID())
	} else {
		entityUserID = protocol.URLEncodedBase64(user.WebAuthnID())
	}

	entityUser := protocol.UserEntity{
		ID:          entityUserID,
		DisplayName: user.WebAuthnDisplayName(),
		CredentialEntity: protocol.CredentialEntity{
			Name: user.WebAuthnName(),
		},
	}

	entityRelyingParty := protocol.RelyingPartyEntity{
		ID: webauthn.Config.RPID,
		CredentialEntity: protocol.CredentialEntity{
			Name: webauthn.Config.RPDisplayName,
		},
	}

	credentialParams := CredentialParametersDefault()

	creation = &protocol.CredentialCreation{
		Response: protocol.PublicKeyCredentialCreationOptions{
			RelyingParty:           entityRelyingParty,
			User:                   entityUser,
			Challenge:              challenge,
			Parameters:             credentialParams,
			AuthenticatorSelection: webauthn.Config.AuthenticatorSelection,
			Attestation:            webauthn.Config.AttestationPreference,
		},
		Mediation: mediation,
	}

	for _, opt := range opts {
		opt(&creation.Response)
	}

	if len(creation.Response.RelyingParty.ID) == 0 {
		return nil, nil, fmt.Errorf("error generating credential creation: the relying party id must be provided via the configuration or a functional option for a creation")
	} else if err = protocol.ValidateRPID(creation.Response.RelyingParty.ID); err != nil {
		return nil, nil, fmt.Errorf("error generating credential creation: the relying party id failed to validate as it's not a valid domain string with error: %w", err)
	}

	if len(creation.Response.RelyingParty.Name) == 0 {
		return nil, nil, fmt.Errorf("error generating credential creation: the relying party display name must be provided via the configuration or a functional option for a creation")
	}

	if creation.Response.Timeout == 0 {
		switch creation.Response.AuthenticatorSelection.UserVerification {
		case protocol.VerificationDiscouraged:
			creation.Response.Timeout = int(webauthn.Config.Timeouts.Registration.TimeoutUVD.Milliseconds())
		default:
			creation.Response.Timeout = int(webauthn.Config.Timeouts.Registration.Timeout.Milliseconds())
		}
	}

	session = &SessionData{
		Challenge:        challenge.String(),
		RelyingPartyID:   creation.Response.RelyingParty.ID,
		UserID:           user.WebAuthnID(),
		UserVerification: creation.Response.AuthenticatorSelection.UserVerification,
		CredParams:       creation.Response.Parameters,
		Mediation:        creation.Mediation,
	}

	if webauthn.Config.Timeouts.Registration.Enforce {
		session.Expires = time.Now().Add(time.Millisecond * time.Duration(creation.Response.Timeout))
	}

	return creation, session, nil
}

// FinishRegistration takes the response from the authenticator and client and verify the credential against the user's
// credentials and session data.
//
// As with all Finish functions this function requires a [*http.Request] but you can perform the same steps with the
// [protocol.ParseCredentialCreationResponseBody] or [protocol.ParseCredentialCreationResponseBytes] which require an
// [io.Reader] or byte array respectively, you can also use an arbitrary [*protocol.ParsedCredentialCreationData] which is
// returned from all of these functions i.e. by implementing a custom parser. The [User], [*SessionData], and
// [*protocol.ParsedCredentialCreationData] can then be used with the [WebAuthn.CreateCredential] function.
func (webauthn *WebAuthn) FinishRegistration(user User, session SessionData, request *http.Request) (credential *Credential, err error) {
	parsedResponse, err := protocol.ParseCredentialCreationResponse(request)
	if err != nil {
		return nil, err
	}

	return webauthn.CreateCredential(user, session, parsedResponse)
}

// CreateCredential verifies a parsed response against the user's credentials and session data.
//
// If you wish to skip performing the step required to parse the [*protocol.ParsedCredentialCreationData] and
// you're using net/http then you can use [WebAuthn.FinishRegistration] instead.
func (webauthn *WebAuthn) CreateCredential(user User, session SessionData, parsedResponse *protocol.ParsedCredentialCreationData) (credential *Credential, err error) {
	if !bytes.Equal(user.WebAuthnID(), session.UserID) {
		return nil, protocol.ErrBadRequest.WithDetails("ID mismatch for User and Session")
	}

	if !session.Expires.IsZero() && session.Expires.Before(time.Now()) {
		return nil, protocol.ErrBadRequest.WithDetails("Session has Expired")
	}

	shouldVerifyUser := session.UserVerification == protocol.VerificationRequired
	shouldVerifyUserPresence := session.Mediation != protocol.MediationConditional

	var (
		attestationType string
		clientDataHash  []byte
	)

	if attestationType, clientDataHash, err = parsedResponse.Verify(session.Challenge, shouldVerifyUser, shouldVerifyUserPresence, webauthn.Config.RPID, webauthn.Config.RPOrigins, webauthn.Config.RPTopOrigins, webauthn.Config.RPTopOriginVerificationMode, webauthn.Config.MDS, session.CredParams); err != nil {
		return nil, err
	}

	return NewCredential(attestationType, clientDataHash, parsedResponse)
}
