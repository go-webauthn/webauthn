package webauthn

import (
	"time"
)

const (
	errFmtFieldNotValidDomainString = "field '%s' is not a valid domain string: %w"
	errFmtConfigValidate            = "error occurred validating the configuration: %w"

	errFmtOriginsNotRelated      = "when the 'RPOpaqueOrigins' field is configured the '%s' field must only contain origins a Related Origin Requests document can declare: %w"
	errFmtOriginsNotRelatedValue = "when the 'RPOpaqueOrigins' field is configured the '%s' field must only contain origins a Related Origin Requests document can declare but the value '%s' is opaque"
	errFmtOriginsNotOpaqueValue  = "the 'RPOpaqueOrigins' field must only contain opaque origins but the value '%s' is not opaque; it belongs in the 'RPOrigins' field"
	errFmtOriginsOpaqueUnknown   = "the 'RPOpaqueOrigins' field must only contain opaque origins a client conveys, i.e. one prefixed with %s, but the value '%s' is not one of them"

	errFmtOriginBindOpaque       = "the ceremony origin '%s' can't be bound as it's opaque and an opaque origin is only conveyed in the ceremony response"
	errFmtOriginBindUnconfigured = "the ceremony origin '%s' must be one of the origins in the 'RPOrigins' configuration"
)

const (
	defaultTimeoutUVD = time.Millisecond * 120000
	defaultTimeout    = time.Millisecond * 300000
)
