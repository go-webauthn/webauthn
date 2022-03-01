# WebAuthn Library

[![GoDoc](https://godoc.org/github.com/go-webauthn/webauthn?status.svg)](https://godoc.org/github.com/go-webauthn/webauthn)
[![Go Report Card](https://goreportcard.com/badge/github.com/go-webauthn/webauthn)](https://goreportcard.com/report/github.com/go-webauthn/webauthn)


This library is meant to handle [Web Authentication](https://w3c.github.io/webauthn) for Go apps that wish to implement 
a passwordless solution for users. While the specification is currently in Candidate Recommendation, this library
conforms as much as possible to the guidelines and implementation procedures outlined by the document.

## Fork

This library is a hard fork of github.com/duo-labs/webauthn however we do not have any affiliation with Duo Labs or any
of the authors. This library should not be seen as a representation of them in any form. The intent of this library is
to address outstanding issues with that library without having to wait on the maintainers to merge the PR's. 

It is distributed under the same 3-Clause BSD license as the original fork, with the only amendment being the additional
3-Clause BSD license attributing license rights to this repository.

### Differences

There are several differences between the upstream library and this one. We will aim to keep this list updated:

* There are minimal breaking changes between this library and the upstream one. Identified breaking changes exist in the 
  following commits:
  *  Change of protocol.ResidentKeyUnrequired() to protocol.ResidentKeyNotRequired() 5ad54f89952eb238a7d6e10ed2d443738351d67f.
* This library is versioned with branches per minor version for back-porting fixes.
* The following PR's in the upstream repository are merged in one form or another:
  * PR132 was merged in 401a3f63b5fb3c91faa52c56a9295b78d62e039f.
  * PR131 was merged in 509e08fb364c78be30067a93d976730a8fe4a656 (cherry-pick squashed).
  * PR130 was merged in 729227d1ec0504ebb518f38e72bcd10ae68c4130 (v0.2.x) and 93a942a90dbb82d997e1ed2945ba41b37d47890f (v0.1.x).
  * PR122 was merged in 2bbb113b333b775d2d7c5551b7220f713f666f00.
  * PR116 was (effectively) merged in d64d2ba780240964310c7f5862add333bc659348.
* The following misc fixes have been merged:
  * Ensuring the credential ID length is not too long in b3b93ac3770a26a92adbcd4b527bbb391127931b (v0.2.x) and 35287ea54b50b1f553f3cc0f0f5527039f375e2c (v0.1.x).
  * Ensuring errors are effectively checked, ineffectual checks are not done, and general linting fixes in 90be0fe276222bd574cf19856081979789ce9fca.

## Status

This library is still version 0, as per semver rules there may be breaking changes without warning. While we strive to
avoid such changes they may be unavoidable.

## Quickstart

`go get github.com/go-webauthn/webauthn` and initialize it in your application with basic configuration values. 

Make sure your `user` model is able to handle the interface functions laid out in `webauthn/user.go`. This means also 
supporting the storage and retrieval of the credential and authenticator structs in `webauthn/credential.go` and 
`webauthn/authenticator.go`, respectively.

### Initialize the request handler

```golang
import (
	"github.com/go-webauthn/webauthn/webauthn"
)

var (
    web *webauthn.WebAuthn
    err error
)

// Your initialization function
func main() {
    web, err = webauthn.New(&webauthn.Config{
        RPDisplayName: "Go Webauthn", // Display Name for your site
        RPID: "go-webauthn.local", // Generally the FQDN for your site
        RPOrigin: "https://login.go-webauthn.local", // The origin URL for WebAuthn requests
        RPIcon: "https://go-webauthn.local/logo.png", // Optional icon URL for your site
    })
    if err != nil {
        fmt.Println(err)
    }
}

```

### Registering an account

```golang
func BeginRegistration(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Find or create the new user  
    options, sessionData, err := web.BeginRegistration(&user)
    // handle errors if present
    // store the sessionData values 
    JSONResponse(w, options, http.StatusOK) // return the options generated
    // options.publicKey contain our registration options
}

func FinishRegistration(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Get the user  
    // Get the session data stored from the function above
    // using gorilla/sessions it could look like this
    sessionData := store.Get(r, "registration-session")
    parsedResponse, err := protocol.ParseCredentialCreationResponseBody(r.Body)
    credential, err := web.CreateCredential(&user, sessionData, parsedResponse)
    // Handle validation or input errors
    // If creation was successful, store the credential object
    JSONResponse(w, "Registration Success", http.StatusOK) // Handle next steps
}
```

### Logging into an account

```golang
func BeginLogin(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Find the user
    options, sessionData, err := webauthn.BeginLogin(&user)
    // handle errors if present
    // store the sessionData values
    JSONResponse(w, options, http.StatusOK) // return the options generated
    // options.publicKey contain our registration options
}

func FinishLogin(w http.ResponseWriter, r *http.Request) {
    user := datastore.GetUser() // Get the user 
    // Get the session data stored from the function above
    // using gorilla/sessions it could look like this
    sessionData := store.Get(r, "login-session")
    parsedResponse, err := protocol.ParseCredentialRequestResponseBody(r.Body)
    credential, err := webauthn.ValidateLogin(&user, sessionData, parsedResponse)
    // Handle validation or input errors
    // If login was successful, handle next steps
    JSONResponse(w, "Login Success", http.StatusOK)
}
```

## Modifying Credential Options

You can modify the default credential creation options for registration and login by providing optional structs to the 
`BeginRegistration` and `BeginLogin` functions. 

### Registration modifiers

You can modify the registration options in the following ways:

```golang
// Wherever you handle your WebAuthn requests
import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthnHandler webauthn.WebAuthn // init this in your init function

func beginRegistration() {
    // Updating the AuthenticatorSelection options. 
    // See the struct declarations for values
    authSelect := protocol.AuthenticatorSelection{        
		AuthenticatorAttachment: protocol.AuthenticatorAttachment("platform"),
		RequireResidentKey: protocol.ResidentKeyUnrequired(),
        UserVerification: protocol.VerificationRequired
    }

    // Updating the ConveyencePreference options. 
    // See the struct declarations for values
    conveyencePref := protocol.ConveyancePreference(protocol.PreferNoAttestation)

    user := datastore.GetUser() // Get the user  
    opts, sessionData, err webAuthnHandler.BeginRegistration(&user, webauthn.WithAuthenticatorSelection(authSelect), webauthn.WithConveyancePreference(conveyancePref))

    // Handle next steps
}
```

### Login modifiers

You can modify the login options to allow only certain credentials:

```golang
// Wherever you handle your WebAuthn requests
import (
	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"
)

var webAuthnHandler webauthn.WebAuthn // init this in your init function

func beginLogin() {
    // Updating the AuthenticatorSelection options. 
    // See the struct declarations for values
    allowList := make([]protocol.CredentialDescriptor, 1)
    allowList[0] = protocol.CredentialDescriptor{
        CredentialID: credentialToAllowID,
        Type: protocol.CredentialType("public-key"),
    }

    user := datastore.GetUser() // Get the user  

    opts, sessionData, err := webAuthnHandler.BeginLogin(&user, webauthn.wat.WithAllowedCredentials(allowList))

    // Handle next steps
}

```

## Acknowledgements

We graciously acknowledge the original authors of this library [github.com/duo-labs/webauthn](https://github.com/duo-labs/webauthn)
for their amazing implementation. Without their amazing work this library could not exist.