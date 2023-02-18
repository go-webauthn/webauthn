package webauthn

import (
	"time"
)

const (
	errFmtEmptyField     = "the field '%s' must be configured but it is empty"
	errFmtConfigValidate = "error occurred validating the configuration: %w"
)

const (
	defaultTimeoutUVD = time.Millisecond * 120000
	defaultTimeout    = time.Millisecond * 300000
)
