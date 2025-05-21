package webauthn_test

import (
	"encoding/json"
	"fmt"
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
	"net/http"
)

var config = &webauthn.Config{}

func ExampleNew() {
	config := &webauthn.Config{
		RPDisplayName: "Go WebAuthn",
		RPID:          "app.awesome-go-webauthn.com",
		RPOrigins:     []string{"https://app.awesome-go-webauthn.com"},
	}

	handler, err := webauthn.New(config)
	if err != nil {
		panic(err)
	}

	_ = handler
}

func ExampleWebAuthn_BeginMediatedRegistration() {
	/*
			This example is a nominal example of creating a Passkey using the high level API. It contains various
			Crude / Abstract examples of elements that are domain logic concerns and are intentionally not implemented
		    within this library.
	*/

	mux := http.NewServeMux()

	mux.HandleFunc("/webauthn/register/start")

	w, err := webauthn.New(config)
	if err != nil {
		panic(err)
	}

	var session *webauthn.SessionData

	// Crude / Abstract example of saving sessions.
	saveSession := func(s *webauthn.SessionData) {
		session = s
	}

	// Crude / Abstract example of loading saved sessions.
	loadSession := func() (s webauthn.SessionData, err error) {
		if session == nil {
			return s, fmt.Errorf("no session found")
		}

		return *session, nil
	}

	handlerCreateChallenge := func(rw http.ResponseWriter, r *http.Request) {
		// Crude / Abstract example of retrieving the user this registration will belong to.
		// This is so the handle / id can be bound to the credential for passkey logins.
		user := GetUser()

		creation, s, err := w.BeginMediatedRegistration(
			user,
			protocol.MediationDefault,
			webauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
			webauthn.WithExclusions(webauthn.Credentials(user.WebAuthnCredentials()).CredentialDescriptors()),
			webauthn.WithExtensions(map[string]any{"credProps": true}),
		)

		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)

			return
		}

		saveSession(s)

		encoder := json.NewEncoder(rw)

		if err = encoder.Encode(creation); err != nil {
			rw.WriteHeader(http.StatusInternalServerError)

			return
		}

		rw.WriteHeader(http.StatusOK)
	}

	handlerVerifyChallengeResponse := func(rw http.ResponseWriter, r *http.Request) {
		// Crude / Abstract example of retrieving the user this registration will belong to.
		// This is so the handle / id can be bound to the credential for passkey logins.
		user := GetUser()

		s, err := loadSession()
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)

			return
		}

		credential, err := w.FinishRegistration(user, s, r)
		if err != nil {
			rw.WriteHeader(http.StatusInternalServerError)

			return
		}

		// Crude / Abstract example of adding the credential to the list of credentials for the user and saving them.
		user.credentials = append(user.credentials, *credential)
	}

	if handlerCreateChallenge == nil || handlerVerifyChallengeResponse == nil {
		panic("handlerCreateChallenge and handlerVerifyChallengeResponse must be set")
	}
}
