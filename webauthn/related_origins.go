package webauthn

import (
	"fmt"

	"github.com/go-webauthn/webauthn/protocol"
)

// RelatedOrigins returns the [protocol.RelatedOrigins] document declaring the origins in [Config.RPOrigins], which is
// what a Relying Party serves at [protocol.WellKnownPathWebAuthn] so clients accept ceremonies from origins which do
// not match [Config.RPID] directly. The returned value is an [net/http.Handler], so it can be mounted as it is:
//
//	related, err := w.RelatedOrigins()
//	if err != nil {
//		return err
//	}
//
//	mux.Handle(protocol.WellKnownPathWebAuthn, related)
//
// The origins are validated and normalized by [protocol.NewRelatedOrigins], so this returns an error when the
// configured origins carry more than [protocol.MaximumRelatedOriginLabels] distinct registrable domain labels, or
// when one of them is opaque. Configuring [Config.RPOpaqueOrigins] holds [Config.RPOrigins] to non-opaque origins at
// validation time, so an opaque origin does not fail this call for a Relying Party whose configuration is unchanged
// since it was validated; the configuration is not validated again here, and [Config.RPOrigins] is read as it is on
// each call. A Relying Party which instead lists its opaque origins in [Config.RPOrigins] must keep them out of the
// document by calling [protocol.NewRelatedOrigins] itself. One whose origins sit under a multi-label public suffix, or
// which lists several subdomains of one registrable domain, should count those labels with a public suffix list by
// calling [protocol.NewRelatedOriginsWithLabeler] with [Config.RPOrigins] instead, and one which serves a set of
// origins other than the configured ones, such as only those which are not same-site with [Config.RPID], should call
// [protocol.NewRelatedOrigins] with that set.
//
// Specification: §5.11. Related Origin Requests (https://www.w3.org/TR/webauthn-3/#sctn-related-origins)
func (webauthn *WebAuthn) RelatedOrigins() (related *protocol.RelatedOrigins, err error) {
	if webauthn == nil || webauthn.Config == nil {
		return nil, fmt.Errorf(errFmtConfigValidate, errConfigNil)
	}

	return protocol.NewRelatedOrigins(webauthn.Config.RPOrigins...)
}
