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
)

const (
	defaultTimeoutUVD = time.Millisecond * 120000
	defaultTimeout    = time.Millisecond * 300000
)
