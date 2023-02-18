package webauthn

const (
	errFmtEmptyField     = "the field '%s' must be configured but it is empty"
	errFmtConfigValidate = "error occurred validating the configuration: %w"
)

const (
	defaultTimeout = 60000
)
