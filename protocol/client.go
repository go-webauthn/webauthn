package protocol

import (
	"crypto/subtle"
	"fmt"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// CollectedClientData represents the contextual bindings of both the WebAuthn Relying Party
// and the client. It is a key-value mapping whose keys are strings. Values can be any type
// that has a valid encoding in JSON. Its structure is defined by the following Web IDL.
//
// Specification: §5.8.1. Client Data Used in WebAuthn Signatures (https://www.w3.org/TR/webauthn/#dictdef-collectedclientdata)
type CollectedClientData struct {
	// Type contains the string "webauthn.create" when creating new credentials, and "webauthn.get" when getting an
	// assertion from an existing credential. The purpose of this member is to prevent certain types of signature
	// confusion attacks (where an attacker substitutes one legitimate signature for another).
	Type CeremonyType `json:"type"`

	// Challenge contains the base64url encoding of the challenge provided by the Relying Party.
	Challenge string `json:"challenge"`

	// Origin contains the fully qualified origin of the requester, as provided to the authenticator by the client.
	Origin string `json:"origin"`

	// TopOrigin contains the fully qualified top-level origin of the requester when the client is cross-origin.
	// This is only present when CrossOrigin is true.
	//
	// WebAuthn Level 3.
	TopOrigin string `json:"topOrigin,omitempty"`

	// CrossOrigin indicates whether the calling context is an iframe that is not same-origin with its ancestor.
	//
	// WebAuthn Level 3.
	CrossOrigin bool `json:"crossOrigin,omitempty"`

	// TokenBinding contains information about the state of the Token Binding protocol.
	//
	// WebAuthn Level 3 removes this member from the CollectedClientData dictionary. It is retained because a client
	// implementing Level 1 or Level 2 may still include it, and a member present in the client data has to be
	// modelled to be validated; it is not something a Relying Party should expect to receive.
	//
	// Deprecated: removed from the CollectedClientData dictionary by WebAuthn Level 3.
	TokenBinding *TokenBinding `json:"tokenBinding,omitempty"`

	// Hint is an opaque field that may be added by the client. Chromium-based browsers include this field to remind
	// implementers not to perform string comparison on the clientDataJSON.
	Hint string `json:"new_keys_may_be_added_here,omitempty"`
}

// CeremonyType represents the type of WebAuthn ceremony being performed.
//
// Specification: §5.8.1. Client Data Used in WebAuthn Signatures (https://www.w3.org/TR/webauthn/#dom-collectedclientdata-type)
type CeremonyType string

const (
	// CreateCeremony is the ceremony type for credential registration ("webauthn.create").
	CreateCeremony CeremonyType = "webauthn.create"

	// AssertCeremony is the ceremony type for authentication assertion ("webauthn.get").
	AssertCeremony CeremonyType = "webauthn.get"
)

// TokenBinding contains information about the state of the Token Binding protocol used when communicating with the
// Relying Party. Its absence indicates that the client doesn't support token binding.
//
// Specification: §5.8.1. Client Data Used in WebAuthn Signatures (https://www.w3.org/TR/webauthn/#dom-collectedclientdata-tokenbinding)
//
// Deprecated: WebAuthn Level 3 removes the tokenBinding member from the CollectedClientData dictionary; see
// [CollectedClientData.TokenBinding].
type TokenBinding struct {
	Status TokenBindingStatus `json:"status"`
	ID     string             `json:"id,omitempty"`
}

// TokenBindingStatus represents the state of Token Binding between the client and the Relying Party.
//
// Deprecated: WebAuthn Level 3 removes the tokenBinding member from the CollectedClientData dictionary; see
// [CollectedClientData.TokenBinding].
type TokenBindingStatus string

const (
	// Present indicates token binding was used when communicating with the
	// Relying Party. In this case, the id member MUST be present.
	Present TokenBindingStatus = "present"

	// Supported indicates the client supports token binding, but it was not
	// negotiated when communicating with the Relying Party.
	Supported TokenBindingStatus = "supported"

	// NotSupported indicates token binding not supported
	// when communicating with the Relying Party.
	//
	// This value is accepted but has not been a member of the TokenBindingStatus enumeration since WebAuthn Level 1,
	// which is why it is not rejected: a client which still sends it is behaving as an older level of the
	// specification allowed, and failing the ceremony over an advisory member would serve no purpose.
	NotSupported TokenBindingStatus = "not-supported"
)

// FullyQualifiedOrigin returns the origin per the HTML spec: (scheme)://(host)[:(port)]. For the http and https schemes
// the host is lowercased, an IPv6 address is written in its canonical form, and the default port of the scheme is
// omitted, as they are in the serialization of an origin.
//
// A known opaque origin which carries no authority component, i.e. one a client conveys for a native application such
// as 'android:apk-key-hash:...' or the origin of a document loaded from the local file system, has no such
// serialization and is returned unaltered so it can be compared byte for byte. The opaque origins which do carry an
// authority, such as the origin of a browser extension, are serialized in the usual way.
func FullyQualifiedOrigin(rawOrigin string) (fqOrigin string, err error) {
	if isOpaqueOriginWithoutAuthority(rawOrigin) {
		return rawOrigin, nil
	}

	var origin *url.URL

	if origin, err = url.ParseRequestURI(rawOrigin); err != nil {
		return "", err
	}

	if origin.Host == "" {
		return "", fmt.Errorf("url '%s' does not have a host", rawOrigin)
	}

	switch origin.Scheme {
	case "http", "https":
		return relatedOriginNormalize(rawOrigin)
	}

	origin.Path, origin.RawPath, origin.RawQuery, origin.ForceQuery, origin.User = "", "", "", false, nil

	return origin.String(), nil
}

// Verify handles steps 3 through 6 of verifying the registering client data of a
// new credential and steps 7 through 10 of verifying an authentication assertion
// See https://www.w3.org/TR/webauthn/#registering-a-new-credential
// and https://www.w3.org/TR/webauthn/#verifying-assertion
//
// Note: the rpTopOriginsVerify parameter does not accept the TopOriginVerificationMode value of
// TopOriginDefaultVerificationMode as it's expected this value is updated by the config validation process.
//
// The rpOpaqueOrigins parameter carries the origins which are not http or https tuple origins, i.e. those for which
// [IsOpaqueOrigin] returns true. They widen the set the ceremony origin is matched against, and only that set; the
// Top Origin is deliberately never matched against them as a Top Origin is by definition the origin of a top-level
// browsing context. They are matched by [IsOpaqueOriginInHaystack], i.e. by simple string comparison, never by the
// origin equality semantics applied to the rpOrigins parameter.
//
//nolint:gocyclo
func (c *CollectedClientData) Verify(storedChallenge string, ceremony CeremonyType, rpOrigins, rpOpaqueOrigins, rpTopOrigins []string, rpTopOriginsVerify TopOriginVerificationMode, allowCrossOrigin bool) (err error) {
	// Registration Step 3. Verify that the value of C.type is webauthn.create.

	// Assertion Step 7. Verify that the value of C.type is the string webauthn.get.
	if c.Type != ceremony {
		return ErrVerification.WithDetails("Error validating ceremony type").WithInfo(fmt.Sprintf("Expected Value: %s, Received: %s", ceremony, c.Type))
	}

	// Registration Step 4. Verify that the value of C.challenge matches the challenge
	// that was sent to the authenticator in the create() call.

	// Assertion Step 8. Verify that the value of C.challenge matches the challenge
	// that was sent to the authenticator in the PublicKeyCredentialRequestOptions
	// passed to the get() call.

	challenge := c.Challenge
	if subtle.ConstantTimeCompare([]byte(storedChallenge), []byte(challenge)) != 1 {
		return ErrVerification.
			WithDetails("Error validating challenge").
			WithInfo(fmt.Sprintf("Expected b Value: %#v\nReceived b: %#v\n", storedChallenge, challenge))
	}

	// Registration Step 5 & Assertion Step 9. Verify that the value of C.origin matches
	// the Relying Party's origin.

	if !IsOriginInHaystack(c.Origin, rpOrigins) && !IsOpaqueOriginInHaystack(c.Origin, rpOpaqueOrigins) {
		possibleOrigins := rpOrigins

		if len(rpOpaqueOrigins) != 0 {
			possibleOrigins = make([]string, 0, len(rpOrigins)+len(rpOpaqueOrigins))
			possibleOrigins = append(possibleOrigins, rpOrigins...)
			possibleOrigins = append(possibleOrigins, rpOpaqueOrigins...)
		}

		return ErrVerification.
			WithDetails("Error validating origin").
			WithInfo(fmt.Sprintf("Expected Values: %s, Received: %s", possibleOrigins, c.Origin))
	}

	if !allowCrossOrigin && c.CrossOrigin {
		return ErrVerification.
			WithDetails("Error validating cross origin flag").
			WithInfo("The cross origin flag is invalid due to the configuration.")
	}

	switch len(c.TopOrigin) {
	case 0:
		break
	default:
		if !c.CrossOrigin {
			return ErrVerification.
				WithDetails("Error validating topOrigin").
				WithInfo("The topOrigin can't have values unless crossOrigin is true.")
		}

		var possibleTopOrigins []string

		switch rpTopOriginsVerify {
		case TopOriginExplicitVerificationMode:
			possibleTopOrigins = rpTopOrigins
		case TopOriginAutoVerificationMode:
			possibleTopOrigins = make([]string, 0, len(rpTopOrigins)+len(rpOrigins))
			possibleTopOrigins = append(possibleTopOrigins, rpTopOrigins...)
			possibleTopOrigins = append(possibleTopOrigins, rpOrigins...)
		case TopOriginImplicitVerificationMode:
			possibleTopOrigins = rpOrigins
		default:
			return ErrNotImplemented.WithDetails("Error handling unknown Top Origin verification mode")
		}

		if !IsOriginInHaystack(c.TopOrigin, possibleTopOrigins) {
			return ErrVerification.
				WithDetails("Error validating top origin").
				WithInfo(fmt.Sprintf("Expected Values: %s, Received: %s", possibleTopOrigins, c.TopOrigin))
		}
	}

	// Registration Step 6 and Assertion Step 10. Verify that the value of C.tokenBinding.status
	// matches the state of Token Binding for the TLS connection over which the assertion was
	// obtained. If Token Binding was used on that TLS connection, also verify that C.tokenBinding.id
	// matches the base64url encoding of the Token Binding ID for the connection.
	if c.TokenBinding != nil {
		if c.TokenBinding.Status == "" {
			return ErrParsingData.WithDetails("Error decoding clientData, token binding present without status")
		}

		if c.TokenBinding.Status != Present && c.TokenBinding.Status != Supported && c.TokenBinding.Status != NotSupported {
			return ErrParsingData.
				WithDetails("Error decoding clientData, token binding present with invalid status").
				WithInfo(fmt.Sprintf("Got: %s", c.TokenBinding.Status))
		}
	}
	// Not yet fully implemented by the spec, browsers, and me.

	return nil
}

// TopOriginVerificationMode determines how the Relying Party validates the topOrigin field in
// [CollectedClientData]. This is relevant for cross-origin iframe scenarios where the top-level browsing context's
// origin differs from the embedded origin making the WebAuthn API call.
//
// WebAuthn Level 3.
type TopOriginVerificationMode int

const (
	// TopOriginDefaultVerificationMode is the zero value of [TopOriginVerificationMode] and has no matching rule in
	// the verifier; passing it directly to [CollectedClientData.Verify] returns an "unknown Top Origin verification
	// mode" error. High-level callers using [webauthn.Config] have this value coerced to
	// [TopOriginExplicitVerificationMode] by config validation, which is the recommended default.
	TopOriginDefaultVerificationMode TopOriginVerificationMode = iota

	// TopOriginAutoVerificationMode accepts the Top Origin if it matches any entry in either the allowed Top Origins
	// list or the allowed Origins list. The two lists are unioned (RPTopOrigins ∪ RPOrigins). This is the most
	// permissive of the three active modes and should only be used when an RP deliberately wants cross-origin and
	// same-origin embeddings to share an allow-list.
	TopOriginAutoVerificationMode

	// TopOriginImplicitVerificationMode accepts the Top Origin only if it matches an entry in the allowed Origins
	// list (RPOrigins). The RPTopOrigins list is ignored in this mode.
	TopOriginImplicitVerificationMode

	// TopOriginExplicitVerificationMode accepts the Top Origin only if it matches an entry in the allowed Top Origins
	// list (RPTopOrigins). The RPOrigins list is ignored in this mode. This is the strictest mode and the one
	// [webauthn.Config] coerces the zero value to.
	TopOriginExplicitVerificationMode
)

// IsOriginInHaystack checks if the needle is in the haystack using the mechanism to determine origin equality defined
// in HTML5 Section 5.3 and RFC3986 Section 6.2.1.
//
// Specifically if the needle value has the 'http://' or 'https://' prefix (case-insensitive) and can be parsed as a
// URL; we check each item in the haystack to see if it matches the same rules, and then if the scheme and host (with
// a normalized port) components match case-insensitively then they're considered a match.
//
// The leniency applies to the needle only when it is the serialization of an origin, i.e. when it has no userinfo,
// path, query, or fragment component, as the value a client conveys never has one. The items in the haystack are
// reduced to their scheme and host before they are compared, so an origin may be configured with any of them.
//
// If the needle value does not have the 'http://' or 'https://' prefix (case-insensitive), can't be parsed as a URL,
// has no host or a port out of range, or has any of the components an origin does not have, equality is determined
// using simple string comparison. An item in the haystack which can't be reduced to a scheme and host in the same
// way is only ever matched by simple string comparison.
//
// It is important to note that this function completely ignores Apple Associated Domains entirely as Apple is using
// an unassigned Well-Known URI in breech of Well-Known Uniform Resource Identifiers (RFC8615).
//
// See (Origin Definition): https://www.w3.org/TR/2011/WD-html5-20110525/origin-0.html
//
// See (Simple String Comparison Definition): https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.1
//
// See (Apple Associated Domains): https://developer.apple.com/documentation/xcode/supporting-associated-domains
//
// See (IANA Well Known URI Assignments): https://www.iana.org/assignments/well-known-uris/well-known-uris.xhtml
//
// See (Well-Known Uniform Resource Identifiers): https://datatracker.ietf.org/doc/html/rfc8615
func IsOriginInHaystack(needle string, haystack []string) bool {
	if origin, ok := normalizeBareOrigin(needle); ok {
		for _, hay := range haystack {
			if normalized, ok := normalizeOrigin(hay); ok && normalized == origin {
				return true
			}
		}
	} else {
		for _, hay := range haystack {
			if needle == hay {
				return true
			}
		}
	}

	return false
}

// IsOpaqueOriginInHaystack checks if the needle is in the haystack of opaque origins, i.e. the origins for which
// [IsOpaqueOrigin] returns true, using simple string comparison as defined in RFC3986 Section 6.2.1.
//
// This is deliberately not [IsOriginInHaystack]: an opaque origin has no scheme and host to normalize, so there is no
// case folding and no port normalization to apply to it, and the value a client conveys for one is compared byte for
// byte or not at all. Routing the opaque origins through this function rather than through [IsOriginInHaystack] keeps
// that true of a value which merely resembles a URL, such as an http origin which has no host or whose port is out of
// range; both are opaque, and neither may be matched with the leniency an origin with a host is matched with.
//
// See (Simple String Comparison Definition): https://datatracker.ietf.org/doc/html/rfc3986#section-6.2.1
func IsOpaqueOriginInHaystack(needle string, haystack []string) bool {
	for _, hay := range haystack {
		if needle == hay {
			return true
		}
	}

	return false
}

func toLowerASCII(s string) string {
	b := []byte(s)

	for i, c := range b {
		if 'A' <= c && c <= 'Z' {
			b[i] = c + ('a' - 'A')
		}
	}

	return string(b)
}

func isBareOrigin(raw string, uri *url.URL) bool {
	return uri.User == nil && uri.Path == "" && uri.RawPath == "" && !strings.ContainsAny(raw, "?#")
}

func normalizeBareOrigin(raw string) (normalized string, ok bool) {
	if !isPossibleFQDN(raw) {
		return "", false
	}

	uri, err := url.Parse(raw)

	if err != nil || !isBareOrigin(raw, uri) {
		return "", false
	}

	return normalizeOrigin(raw)
}

func normalizeOrigin(raw string) (normalized string, ok bool) {
	if !isPossibleFQDN(raw) {
		return "", false
	}

	normalized, err := relatedOriginNormalize(raw)

	return normalized, err == nil
}

func canonicalOriginHost(uri *url.URL) string {
	host := uri.Host

	if port := uri.Port(); port != "" {
		canonical := strings.TrimLeft(port, "0")

		if canonical == "" {
			canonical = "0"
		}

		host = strings.TrimSuffix(host, port) + canonical
	}

	if end := strings.IndexByte(host, ']'); end != -1 && strings.HasPrefix(host, "[") {
		if addr, err := netip.ParseAddr(host[1:end]); err == nil && addr.Is6() && addr.Zone() == "" {
			host = "[" + serializeIPv6(addr) + host[end:]
		}
	}

	return host
}

func serializeIPv6(addr netip.Addr) string {
	var pieces [8]uint16

	raw := addr.As16()

	for i := range pieces {
		pieces[i] = uint16(raw[2*i])<<8 | uint16(raw[2*i+1])
	}

	start, length := -1, 1

	for i := 0; i < len(pieces); i++ {
		if pieces[i] != 0 {
			continue
		}

		j := i

		for j < len(pieces) && pieces[j] == 0 {
			j++
		}

		if j-i > length {
			start, length = i, j-i
		}

		i = j
	}

	var b strings.Builder

	for i := 0; i < len(pieces); i++ {
		if i == start {
			b.WriteString("::")

			i += length - 1

			continue
		}

		if i != 0 && i != start+length {
			b.WriteByte(':')
		}

		b.WriteString(strconv.FormatUint(uint64(pieces[i]), 16))
	}

	return b.String()
}

func isPossibleFQDN(raw string) bool {
	normalized := strings.ToLower(raw)

	return strings.HasPrefix(normalized, "http://") || strings.HasPrefix(normalized, "https://")
}
