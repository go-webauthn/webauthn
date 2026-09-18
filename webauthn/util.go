package webauthn

import (
	"bytes"
	"encoding/base64"
	"fmt"
	"strings"

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

// validateUserHandle checks a user entity id against the user handle bounds. The member is typed as an any because it
// is encoded either as a base64url string or as a plain string depending on [Config.EncodeUserIDAsString], and because
// a [RegistrationOption] supplied by the caller may replace it with either form. An id of any other type cannot be
// measured against the bounds and is rejected rather than passed to the client.
//
// A client throws a TypeError when the length of the handle it is given is not between 1 and 64 bytes inclusive, so
// a ceremony every user agent would reject fails here instead. The handle itself is not returned because the id which
// is sent to the client is only ever validated here; the value the ceremony is completed against is the id of the
// [User], which the caller already holds.
//
// Specification: §5.1.3. Create a New Credential, step 5 (https://www.w3.org/TR/webauthn-3/#sctn-createCredential)
func validateUserHandle(id any) (err error) {
	var handle []byte

	switch v := id.(type) {
	case protocol.URLEncodedBase64:
		handle = v
	case []byte:
		handle = v
	case string:
		handle = []byte(v)
	default:
		return fmt.Errorf("the user id must be a string, []byte, or protocol.URLEncodedBase64 but it has a type of %T", id)
	}

	if n := len(handle); n < protocol.MinimumUserHandleLength || n > protocol.MaximumUserHandleLength {
		return fmt.Errorf("the user id must be between %d and %d bytes but it has a length of %d", protocol.MinimumUserHandleLength, protocol.MaximumUserHandleLength, n)
	}

	return nil
}

// validateSessionChallenge validates the challenge recorded in the [SessionData] when a ceremony is finished. It must be
// the unpadded base64url encoding of at least [protocol.MinimumChallengeLength] bytes, which is what beginning a
// ceremony produces. This is a backstop for session data that was lost, zero-valued, or tampered with by the session
// store, as an empty challenge would otherwise match an empty challenge in the client data.
//
// Specification: §7.1. Registering a New Credential, step 8 (https://www.w3.org/TR/webauthn-3/#sctn-registering-a-new-credential)
//
// Specification: §7.2. Verifying an Authentication Assertion, step 11 (https://www.w3.org/TR/webauthn-3/#sctn-verifying-assertion)
func validateSessionChallenge(challenge string) (err error) {
	var raw []byte

	if raw, err = base64.RawURLEncoding.DecodeString(challenge); err != nil {
		return protocol.ErrBadRequest.WithDetails("Session has an invalid challenge").WithInfo(fmt.Sprintf("The challenge could not be decoded: %+v", err)).WithError(err)
	}

	if n := len(raw); n < protocol.MinimumChallengeLength {
		return protocol.ErrBadRequest.WithDetails("Session has an invalid challenge").WithInfo(fmt.Sprintf("The challenge must be at least %d bytes but it has a length of %d", protocol.MinimumChallengeLength, n))
	}

	return nil
}

// joinOpaqueOriginPrefixes renders the prefixes of [protocol.OpaqueOriginPrefixes] for an error message, i.e. as
// "'a', 'b', or 'c'".
func joinOpaqueOriginPrefixes() string {
	prefixes := protocol.OpaqueOriginPrefixes()

	for i, prefix := range prefixes {
		prefixes[i] = "'" + prefix + "'"
	}

	switch n := len(prefixes); n {
	case 0:
		return ""
	case 1:
		return prefixes[0]
	default:
		return strings.Join(prefixes[:n-1], ", ") + ", or " + prefixes[n-1]
	}
}

// validateCeremonyOrigin checks the origin a ceremony is being bound to by [WithRegistrationOrigin] or
// [WithLoginOrigin] against the origins the Relying Party is configured with.
func validateCeremonyOrigin(origin string, rpOrigins []string) (err error) {
	if protocol.IsOpaqueOrigin(origin) {
		return fmt.Errorf(errFmtOriginBindOpaque, origin)
	}

	if !protocol.IsOriginInHaystack(origin, rpOrigins) {
		return fmt.Errorf(errFmtOriginBindUnconfigured, origin)
	}

	return nil
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
