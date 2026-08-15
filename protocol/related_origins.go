package protocol

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const (
	// WellKnownPathWebAuthn is the path of the well-known resource a Relying Party serves to declare the origins
	// related to its Relying Party ID. A client fetches it from https://<rpid>/.well-known/webauthn when the origin
	// of a ceremony does not match the Relying Party ID directly.
	//
	// Specification: §5.11. Related Origin Requests (https://www.w3.org/TR/webauthn-3/#sctn-related-origins)
	WellKnownPathWebAuthn = "/.well-known/webauthn"

	// MaximumRelatedOriginLabels is the number of distinct registrable domain labels a client processes when it reads
	// the well-known resource. A client stops adding labels once it has seen this many, so origins whose label falls
	// outside the budget are silently ignored; this is the limit [NewRelatedOrigins] holds the origins to.
	//
	// Specification: §5.11. Related Origin Requests (https://www.w3.org/TR/webauthn-3/#sctn-related-origins)
	MaximumRelatedOriginLabels = 5
)

const (
	headerAllow         = "Allow"
	headerContentType   = "Content-Type"
	headerContentLength = "Content-Length"

	mimeApplicationJSON = "application/json"

	methodsRelatedOrigins = http.MethodGet + ", " + http.MethodHead

	maximumPort = 65535
)

// RelatedOriginLabeler derives the registrable domain label of an origin, which is the unit a client counts against
// [MaximumRelatedOriginLabels]. Origins which share a label cost only one between them, which is what lets a Relying
// Party list the same brand across many country code top level domains cheaply.
//
// [DefaultRelatedOriginLabeler] is used when none is supplied. Supply your own to count labels exactly for a
// deployment which uses a multi-label public suffix; see that function for why the default cannot.
type RelatedOriginLabeler func(origin string) (label string, err error)

// RelatedOrigins is the document a Relying Party serves at [WellKnownPathWebAuthn] to declare which origins may run
// ceremonies against its Relying Party ID.
//
// Build one with [NewRelatedOrigins], which validates and normalizes the origins, then serve it with whichever of
// [RelatedOrigins.Bytes], [RelatedOrigins.WriteTo] or [RelatedOrigins.WriteResponse] suits the surrounding code. The
// type is also an [http.Handler], so it can be mounted on a router directly:
//
//	related, err := protocol.NewRelatedOrigins("https://example.com", "https://example.com.au")
//	if err != nil {
//		return err
//	}
//
//	mux.Handle(protocol.WellKnownPathWebAuthn, related)
//
// A [WebAuthn.RelatedOrigins] method in the webauthn package builds this from the configured origins.
//
// Specification: §5.11. Related Origin Requests (https://www.w3.org/TR/webauthn-3/#sctn-related-origins)
type RelatedOrigins struct {
	Origins []string `json:"origins"`
}

// NewRelatedOrigins validates the given origins and returns the [RelatedOrigins] document which declares them, using
// [DefaultRelatedOriginLabeler] to count the registrable domain labels. See [NewRelatedOriginsWithLabeler] for the
// validation performed and for supplying a labeler of your own.
func NewRelatedOrigins(origins ...string) (related *RelatedOrigins, err error) {
	return NewRelatedOriginsWithLabeler(nil, origins...)
}

// NewRelatedOriginsWithLabeler validates the given origins and returns the [RelatedOrigins] document which declares
// them, counting registrable domain labels with the given [RelatedOriginLabeler]. A nil labeler selects
// [DefaultRelatedOriginLabeler].
//
// Each origin must be an absolute http or https URL with a host. Every origin is normalized to its scheme and host
// alone, with a default port and any path, query, fragment or userinfo removed, and origins which normalize to the
// same value are collapsed to one. The order the origins were given in is otherwise preserved.
//
// An error is returned when the origins carry more than [MaximumRelatedOriginLabels] distinct labels, because a
// client stops processing at that point and the excess origins would be ignored in production without any signal
// that they had been.
func NewRelatedOriginsWithLabeler(labeler RelatedOriginLabeler, origins ...string) (related *RelatedOrigins, err error) {
	if len(origins) == 0 {
		return nil, errors.New("error validating related origins: at least one origin is required")
	}

	if labeler == nil {
		labeler = DefaultRelatedOriginLabeler
	}

	var (
		normalized []string
		origin     string
		label      string
	)

	seen := make(map[string]struct{}, len(origins))
	labels := make(map[string]struct{}, len(origins))

	for _, raw := range origins {
		if origin, err = relatedOriginNormalize(raw); err != nil {
			return nil, fmt.Errorf("error validating related origin '%s': %w", raw, err)
		}

		if _, ok := seen[origin]; ok {
			continue
		}

		seen[origin] = struct{}{}

		if label, err = labeler(origin); err != nil {
			return nil, fmt.Errorf("error validating related origin '%s': error determining the registrable domain label: %w", raw, err)
		}

		labels[label] = struct{}{}

		normalized = append(normalized, origin)
	}

	if n := len(labels); n > MaximumRelatedOriginLabels {
		return nil, fmt.Errorf("error validating related origins: the origins have %d distinct registrable domain labels but clients only process %d of them, so origins beyond that limit are ignored", n, MaximumRelatedOriginLabels)
	}

	return &RelatedOrigins{Origins: normalized}, nil
}

// MarshalJSON implements the [json.Marshaler] interface, encoding an absent origin list as an empty array rather than
// as null so that the document is always the shape a client parses.
func (r RelatedOrigins) MarshalJSON() (data []byte, err error) {
	type alias RelatedOrigins

	if r.Origins == nil {
		return json.Marshal(alias{Origins: []string{}})
	}

	return json.Marshal(alias(r))
}

// Bytes returns the encoded well-known document.
func (r RelatedOrigins) Bytes() (data []byte, err error) {
	return json.Marshal(r)
}

// WriteTo writes the encoded well-known document to the given [io.Writer], implementing the [io.WriterTo] interface.
func (r RelatedOrigins) WriteTo(w io.Writer) (n int64, err error) {
	var data []byte

	if data, err = r.Bytes(); err != nil {
		return 0, err
	}

	var written int

	written, err = w.Write(data)

	return int64(written), err
}

// WriteResponse writes the encoded well-known document to the given [http.ResponseWriter] along with the headers
// which describe it, responding with a status of 200. No caching headers are set; the caching policy of the resource
// is left to the Relying Party.
//
// Use [RelatedOrigins.ServeHTTP] instead to have the request method handled as well.
func (r RelatedOrigins) WriteResponse(w http.ResponseWriter) (err error) {
	var data []byte

	if data, err = r.Bytes(); err != nil {
		return err
	}

	w.Header().Set(headerContentType, mimeApplicationJSON)
	w.Header().Set(headerContentLength, strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)

	_, err = w.Write(data)

	return err
}

// ServeHTTP implements the [http.Handler] interface so the document can be mounted on a router at
// [WellKnownPathWebAuthn] directly. The resource is read only, so a request with a method other than GET or HEAD is
// answered with a status of 405 and an Allow header.
func (r RelatedOrigins) ServeHTTP(w http.ResponseWriter, request *http.Request) {
	switch request.Method {
	case http.MethodGet, http.MethodHead:
		break
	default:
		w.Header().Set(headerAllow, methodsRelatedOrigins)
		w.WriteHeader(http.StatusMethodNotAllowed)

		return
	}

	var (
		data []byte
		err  error
	)

	if data, err = r.Bytes(); err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)

		return
	}

	w.Header().Set(headerContentType, mimeApplicationJSON)
	w.Header().Set(headerContentLength, strconv.Itoa(len(data)))
	w.WriteHeader(http.StatusOK)

	// A response to HEAD carries the headers which describe the document but not the document itself.
	if request.Method == http.MethodHead {
		return
	}

	//nolint:errcheck // The headers have been written, so a failed body write can only be reported by hanging up.
	w.Write(data)
}

// DefaultRelatedOriginLabeler derives the registrable domain label of an origin by taking the leading label of the
// last two labels of its host. An IP address literal, and a host of a single label such as localhost, is its own
// label.
//
// This is exact when the public suffix of the host is a single label, which covers https://example.com and
// https://www.example.com alike, and it is deliberately imprecise otherwise: the public suffix of
// https://example.co.uk is two labels, so this returns 'co' where the registrable domain label is 'example'. The
// effect is to over-count against [MaximumRelatedOriginLabels], which rejects a set of origins a client would have
// accepted rather than serving one a client would truncate.
//
// A deployment which lists origins under a multi-label public suffix should count labels exactly by passing a
// labeler backed by a public suffix list to [NewRelatedOriginsWithLabeler]; this module does not depend on such a
// list so that consumers who do not need one do not carry it:
//
//	labeler := func(origin string) (label string, err error) {
//		uri, err := url.Parse(origin)
//		if err != nil {
//			return "", err
//		}
//
//		domain, err := publicsuffix.EffectiveTLDPlusOne(uri.Hostname())
//		if err != nil {
//			return "", err
//		}
//
//		label, _, _ = strings.Cut(domain, ".")
//
//		return label, nil
//	}
func DefaultRelatedOriginLabeler(origin string) (label string, err error) {
	var uri *url.URL

	if uri, err = url.Parse(origin); err != nil {
		return "", fmt.Errorf("error parsing origin '%s': %w", origin, err)
	}

	host := uri.Hostname()

	if host == "" {
		return "", fmt.Errorf("error determining the label of origin '%s': the origin has no host component", origin)
	}

	// A fully qualified host may carry a trailing root label, which is not one of the labels being counted.
	host = strings.ToLower(strings.TrimSuffix(host, "."))

	if ip := net.ParseIP(host); ip != nil {
		return host, nil
	}

	labels := strings.Split(host, ".")

	if len(labels) < 2 {
		return host, nil
	}

	return labels[len(labels)-2], nil
}

const (
	// OpaqueOriginPrefixAndroidAPKKeyHash is the prefix of the opaque origin a client on Android conveys for a native
	// application. The remainder is the base64url encoding, without padding, of the SHA-1 digest of the signing
	// certificate of the APK.
	OpaqueOriginPrefixAndroidAPKKeyHash = "android:apk-key-hash:"

	// OpaqueOriginPrefixAndroidAPKKeyHashSHA256 is the prefix of the opaque origin a client on Android conveys for a
	// native application when the digest of the signing certificate of the APK is taken with SHA-256 rather than the
	// SHA-1 of [OpaqueOriginPrefixAndroidAPKKeyHash].
	OpaqueOriginPrefixAndroidAPKKeyHashSHA256 = "android:apk-key-hash-sha256:"

	// OpaqueOriginPrefixAndroidAPKKeyID is the prefix of the opaque origin a client on Android conveys for a native
	// application when it identifies the signing key of the APK by its id rather than by a digest of the signing
	// certificate.
	OpaqueOriginPrefixAndroidAPKKeyID = "android:apk-key-id:"

	// OpaqueOriginPrefixIOSBundleID is the prefix of the opaque origin a client on iOS conveys for a native
	// application. The remainder is the bundle identifier of the application.
	OpaqueOriginPrefixIOSBundleID = "ios:bundle-id:"

	// OpaqueOriginPrefixIOSBundleKey is the prefix of the opaque origin a client on iOS conveys for a native
	// application when it identifies the application by its signing key rather than by the bundle identifier of
	// [OpaqueOriginPrefixIOSBundleID].
	OpaqueOriginPrefixIOSBundleKey = "ios:bundle-key:"

	// OpaqueOriginPrefixChromeExtension is the prefix of the origin a Chromium based browser conveys for an extension.
	// The remainder is the id of the extension.
	OpaqueOriginPrefixChromeExtension = "chrome-extension://"

	// OpaqueOriginPrefixMozExtension is the prefix of the origin Firefox conveys for an extension. The remainder is
	// the id the browser assigned the extension for the profile it is installed in, which differs between
	// installations of the same extension.
	OpaqueOriginPrefixMozExtension = "moz-extension://"

	// OpaqueOriginPrefixFile is the origin a browser conveys for a document loaded from the local file system. A file
	// origin has no host to serialize, so this is a complete origin rather than a prefix and a client conveys it
	// exactly as it is given here; see [IsKnownOpaqueOrigin].
	OpaqueOriginPrefixFile = "file://"

	// OpaqueOriginPrefixMSAppX is the prefix of the origin a client conveys for a Windows application package. The
	// remainder is the package identity of the application.
	OpaqueOriginPrefixMSAppX = "ms-appx://"
)

// opaqueOriginPrefixes is the set of prefixes [IsKnownOpaqueOrigin] accepts. The order is the order the prefixes are
// rendered in when a caller lists them for a user, so the forms of one platform sit together.
var opaqueOriginPrefixes = []string{
	OpaqueOriginPrefixAndroidAPKKeyHash,
	OpaqueOriginPrefixAndroidAPKKeyHashSHA256,
	OpaqueOriginPrefixAndroidAPKKeyID,
	OpaqueOriginPrefixIOSBundleID,
	OpaqueOriginPrefixIOSBundleKey,
	OpaqueOriginPrefixChromeExtension,
	OpaqueOriginPrefixMozExtension,
	OpaqueOriginPrefixFile,
	OpaqueOriginPrefixMSAppX,
}

// opaqueOriginsComplete is the set of opaque origins which are complete as they are, i.e. those a client conveys with
// nothing following the prefix because the origin has no host to serialize. They are the exception to the rule
// [hasOpaqueOriginPrefix] otherwise applies, which is that a prefix on its own is a value no client ever conveys.
var opaqueOriginsComplete = []string{
	OpaqueOriginPrefixFile,
}

// OpaqueOriginPrefixes returns the prefixes of the opaque origins this library knows a client conveys, i.e. those
// which [IsKnownOpaqueOrigin] accepts.
func OpaqueOriginPrefixes() []string {
	prefixes := make([]string, len(opaqueOriginPrefixes))

	copy(prefixes, opaqueOriginPrefixes)

	return prefixes
}

// IsOpaqueOrigin returns true when the origin is not one a [RelatedOrigins] document can express, i.e. anything which
// is not an absolute http or https URL with a host component. An opaque origin is matched by simple string comparison
// rather than by the origin equality semantics of [IsOriginInHaystack], and a client never resolves one through the
// well-known resource, so a Relying Party which accepts an opaque origin such as 'android:apk-key-hash:...' declares
// it separately from the origins it serves at [WellKnownPathWebAuthn].
//
// This says nothing about whether a client conveys the origin; see [IsKnownOpaqueOrigin] for that.
//
// Specification: §5.11. Related Origin Requests (https://www.w3.org/TR/webauthn-3/#sctn-related-origins)
func IsOpaqueOrigin(origin string) bool {
	_, err := relatedOriginNormalize(origin)

	return err != nil
}

// IsKnownOpaqueOrigin returns true when the origin is opaque per [IsOpaqueOrigin] and additionally carries one of the
// prefixes of [OpaqueOriginPrefixes] followed by at least one character, or is one of the few such prefixes which is a
// complete origin in itself, i.e. [OpaqueOriginPrefixFile]. Those are the forms a client is known to convey for a
// native application, a browser extension, or a document loaded from the local file system, which are the only opaque
// origins a Relying Party can meaningfully accept: an opaque origin is matched by simple string comparison against a
// value the Relying Party configured, so a value no client ever produces can only ever fail to match.
//
// The prefix is matched case-sensitively, as the whole value is, because a client conveys these origins in the form
// given here and the origin as a whole is compared byte for byte.
func IsKnownOpaqueOrigin(origin string) bool {
	return hasOpaqueOriginPrefix(origin) && IsOpaqueOrigin(origin)
}

// hasOpaqueOriginPrefix reports whether the origin begins with one of [opaqueOriginPrefixes] and carries a value after
// it, or is one of [opaqueOriginsComplete].
//
// A complete opaque origin is matched only as itself and never as a prefix, as the value a client conveys for it ends
// where the prefix does; appending to it, i.e. 'file://localhost', produces a value no client conveys.
func hasOpaqueOriginPrefix(origin string) bool {
	if isOpaqueOriginComplete(origin) {
		return true
	}

	for _, prefix := range opaqueOriginPrefixes {
		if isOpaqueOriginComplete(prefix) {
			continue
		}

		if len(origin) > len(prefix) && strings.HasPrefix(origin, prefix) {
			return true
		}
	}

	return false
}

// isOpaqueOriginWithoutAuthority reports whether the origin is a known opaque origin which has no authority component
// for a URL parser to reduce to a scheme and host, i.e. one whose prefix is a scheme and a value rather than a scheme
// and the '//' which introduces an authority, or one which is complete as it is because its authority is empty. Those
// are the origins [FullyQualifiedOrigin] returns unaltered; the ones with an authority have a serialization it can
// derive in the usual way.
func isOpaqueOriginWithoutAuthority(origin string) bool {
	if isOpaqueOriginComplete(origin) {
		return true
	}

	for _, prefix := range opaqueOriginPrefixes {
		if strings.HasSuffix(prefix, "//") {
			continue
		}

		if len(origin) > len(prefix) && strings.HasPrefix(origin, prefix) {
			return true
		}
	}

	return false
}

// isOpaqueOriginComplete reports whether the origin is one of [opaqueOriginsComplete].
func isOpaqueOriginComplete(origin string) bool {
	for _, complete := range opaqueOriginsComplete {
		if origin == complete {
			return true
		}
	}

	return false
}

// relatedOriginNormalize reduces an origin to the scheme and host which identify it, rejecting values which are not
// an origin a client could match a ceremony against.
func relatedOriginNormalize(origin string) (normalized string, err error) {
	var uri *url.URL

	if uri, err = url.Parse(origin); err != nil || uri.Scheme == "" {
		return "", errors.New("the origin must be an absolute URL with a http or https scheme")
	}

	scheme := strings.ToLower(uri.Scheme)

	switch scheme {
	case "http", "https":
		break
	default:
		return "", fmt.Errorf("the scheme must be either http or https but it is '%s'", uri.Scheme)
	}

	if uri.Hostname() == "" {
		return "", errors.New("the origin must have a host component")
	}

	host := strings.ToLower(uri.Host)

	if port := uri.Port(); port == "" {
		// A host may carry a colon with no port after it, which is not part of the serialization of an origin.
		host = strings.TrimSuffix(host, ":")
	} else {
		var number int

		if number, err = strconv.Atoi(port); err != nil || number > maximumPort {
			return "", fmt.Errorf("the port must be no greater than %d but it is '%s'", maximumPort, port)
		}
	}

	// The default port of the scheme is not part of the serialization of an origin. Trimming the suffix rather than
	// rebuilding from the hostname preserves the brackets of an IPv6 address literal.
	switch scheme {
	case "http":
		host = strings.TrimSuffix(host, ":80")
	case "https":
		host = strings.TrimSuffix(host, ":443")
	}

	return (&url.URL{Scheme: scheme, Host: host}).String(), nil
}
