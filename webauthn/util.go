package webauthn

import (
	"bytes"

	"github.com/go-webauthn/webauthn/protocol"
)

func isByteArrayInSlice(needle []byte, haystack ...[]byte) (valid bool) {
	for _, hay := range haystack {
		if bytes.Equal(needle, hay) {
			return true
		}
	}

	return false
}

func isCredentialsAllowedMatchingOwned(allowedCredentialIDs [][]byte, credentials []Credential) (valid bool) {
	var credential Credential

allowed:
	for _, allowedCredentialID := range allowedCredentialIDs {
		for _, credential = range credentials {
			if bytes.Equal(credential.ID, allowedCredentialID) {
				continue allowed
			}
		}

		return false
	}

	return true
}

func isCredentialIDInCredentials(credentialID []byte, credentials []Credential) (valid bool) {
	for _, credential := range credentials {
		if bytes.Equal(credential.ID, credentialID) {
			return true
		}
	}

	return false
}

// ptr returns a pointer to the given value.
func ptr[T any](v T) *T {
	return &v
}

// hasU2FCredential reports whether any of the given descriptors originated from the legacy FIDO U2F JavaScript
// API, which is the condition under which the FIDO AppID and AppID Exclusion extensions are meaningful.
func hasU2FCredential(credentials []protocol.CredentialDescriptor) bool {
	for _, credential := range credentials {
		if credential.AttestationFormat == string(protocol.AttestationFormatFIDOUniversalSecondFactor) {
			return true
		}
	}

	return false
}
