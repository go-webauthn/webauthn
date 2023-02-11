package webauthn

import (
	"fmt"
	"net/url"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
)

// New creates a new WebAuthn object given the proper Config.
func New(config *Config) (*WebAuthn, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("Configuration error: %+v", err)
	}

	return &WebAuthn{
		config,
	}, nil
}

// WebAuthn is the primary interface of this package and contains the request handlers that should be called.
type WebAuthn struct {
	Config *Config
}

// Config represents the WebAuthn configuration.
type Config struct {
	// RPDisplayName configures the display name for the Relying Party Server. This can be any string.
	RPDisplayName string

	// RPID configures the Relying Party Server ID. This should generally be the origin without a scheme and port.
	RPID string

	// RPOrigins configures the list of Relying Party Server Origins that are permitted. These should be fully
	// qualified origins.
	RPOrigins []string

	// RPIcon
	RPIcon string

	// AttestationPreference sets the default attestation conveyance preferences.
	AttestationPreference protocol.ConveyancePreference

	// AuthenticatorSelection sets the default authenticator selection options.
	AuthenticatorSelection protocol.AuthenticatorSelection

	// Debug enables various debug options.
	Debug bool

	// Timeout configures the default timeout in milliseconds.
	//
	// Deprecated: Use Timeouts instead.
	Timeout int

	// Timeouts configures various timeouts.
	Timeouts TimeoutsConfig

	// RPOrigin configures the permitted Relying Party Server Origin.
	//
	// Deprecated: Use RPOrigins instead.
	RPOrigin string

	validated bool
}

// TimeoutsConfig represents the WebAuthn timeouts configuration.
type TimeoutsConfig struct {
	Login        TimeoutConfig
	Registration TimeoutConfig
}

// TimeoutConfig represents the WebAuthn timeouts configuration for either registration or login..
type TimeoutConfig struct {
	// Enforce the timeouts at the Relying Party / Server. This means if enabled and the user takes too long that even
	// if the browser does not enforce the timeout the Relying Party / Server will.
	Enforce bool

	// Timeout is the timeout for logins/registrations when the UserVerificationRequirement is set to anything other
	// than discouraged.
	Timeout time.Duration

	// TimeoutUVD is the timeout for logins/registrations when the UserVerificationRequirement is set to discouraged.
	TimeoutUVD time.Duration
}

// Validate that the config flags in Config are properly set
func (config *Config) validate() error {
	if config.validated {
		return nil
	}

	if len(config.RPDisplayName) == 0 {
		return fmt.Errorf("Missing RPDisplayName")
	}

	if len(config.RPID) == 0 {
		return fmt.Errorf("Missing RPID")
	}

	_, err := url.Parse(config.RPID)
	if err != nil {
		return fmt.Errorf("RPID not valid URI: %+v", err)
	}

	defaultTimeoutConfig := defaultTimeout
	defaultTimeoutUVDConfig := defaultTimeoutUVD

	if config.Timeout != 0 {
		defaultTimeoutConfig = time.Millisecond * time.Duration(config.Timeout)
		defaultTimeoutUVDConfig = defaultTimeoutConfig
	}

	if config.Timeouts.Login.Timeout.Milliseconds() == 0 {
		config.Timeouts.Login.Timeout = defaultTimeoutConfig
	}

	if config.Timeouts.Login.TimeoutUVD.Milliseconds() == 0 {
		config.Timeouts.Login.TimeoutUVD = defaultTimeoutUVDConfig
	}

	if config.Timeouts.Registration.Timeout.Milliseconds() == 0 {
		config.Timeouts.Registration.Timeout = defaultTimeoutConfig
	}

	if config.Timeouts.Registration.TimeoutUVD.Milliseconds() == 0 {
		config.Timeouts.Registration.TimeoutUVD = defaultTimeoutUVDConfig
	}

	if len(config.RPOrigin) > 0 {
		config.RPOrigins = append(config.RPOrigins, config.RPOrigin)
	}

	if len(config.RPOrigins) == 0 {
		return fmt.Errorf("missing at least one RPOrigin")
	}

	if config.AuthenticatorSelection.RequireResidentKey == nil {
		rrk := false
		config.AuthenticatorSelection.RequireResidentKey = &rrk
	}

	if config.AuthenticatorSelection.UserVerification == "" {
		config.AuthenticatorSelection.UserVerification = protocol.VerificationPreferred
	}

	config.validated = true

	return nil
}

// User is built to interface with the Relying Party's User entry and elaborate the fields and methods needed for
// WebAuthn.
type User interface {
	// WebAuthnID returns the ID of the User.
	WebAuthnID() []byte

	// WebAuthnName returns the username of the User.
	WebAuthnName() string

	// WebAuthnDisplayName returns the display name of the User.
	WebAuthnDisplayName() string

	// WebAuthnIcon returns the icon URL of the User.
	WebAuthnIcon() string

	// WebAuthnCredentials returns the Credential list owned by the User.
	WebAuthnCredentials() []Credential
}

// SessionData is the data that should be stored by the Relying Party for
// the duration of the web authentication ceremony
type SessionData struct {
	Challenge            string                               `json:"challenge"`
	UserID               []byte                               `json:"user_id"`
	AllowedCredentialIDs [][]byte                             `json:"allowed_credentials,omitempty"`
	Expires              time.Time                            `json:"expires"`
	UserVerification     protocol.UserVerificationRequirement `json:"userVerification"`
	Extensions           protocol.AuthenticationExtensions    `json:"extensions,omitempty"`
}
