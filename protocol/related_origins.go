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

	if uri.Host == "" {
		return "", errors.New("the origin must have a host component")
	}

	host := strings.ToLower(uri.Host)

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
