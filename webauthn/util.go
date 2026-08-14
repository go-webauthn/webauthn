package webauthn

import (
	"bytes"
	"fmt"

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

// userHandle returns the byte form of a user entity id, having checked it against the user handle bounds. The member
// is typed as an any because it is encoded either as a base64url string or as a plain string depending on
// [Config.EncodeUserIDAsString], and because a [RegistrationOption] supplied by the caller may replace it with either
// form. An id of any other type cannot be measured against the bounds and is rejected rather than passed to the
// client.
//
// A client throws a TypeError when the length of the handle it is given is not between 1 and 64 bytes inclusive, so
// a ceremony every user agent would reject fails here instead.
//
// Specification: §5.1.3. Create a New Credential, step 5 (https://www.w3.org/TR/webauthn-3/#sctn-createCredential)
func userHandle(id any) (handle []byte, err error) {
	switch v := id.(type) {
	case protocol.URLEncodedBase64:
		handle = v
	case []byte:
		handle = v
	case string:
		handle = []byte(v)
	default:
		return nil, fmt.Errorf("the user id must be a string, []byte, or protocol.URLEncodedBase64 but it has a type of %T", id)
	}

	if n := len(handle); n < protocol.MinimumUserHandleLength || n > protocol.MaximumUserHandleLength {
		return nil, fmt.Errorf("the user id must be between %d and %d bytes but it has a length of %d", protocol.MinimumUserHandleLength, protocol.MaximumUserHandleLength, n)
	}

	return handle, nil
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
