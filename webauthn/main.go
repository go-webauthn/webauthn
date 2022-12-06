package webauthn

import (
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
)

var defaultTimeout = 60000

// WebAuthn is the primary interface of this package and contains the request handlers that should be called.
type WebAuthn struct {
	Config *Config
}

// The config values required for proper
type Config struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
	RPIcon        string
	// Defaults for generating options
	AttestationPreference  protocol.ConveyancePreference
	AuthenticatorSelection protocol.AuthenticatorSelection

	Timeout int
	Debug   bool
}

// Validate that the config flags in Config are properly set
func (config *Config) validate() error {
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

	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
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

	return nil
}

// Create a new WebAuthn object given the proper config flags
func New(config *Config) (*WebAuthn, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf("Configuration error: %+v", err)
	}
	return &WebAuthn{
		config,
	}, nil
}
