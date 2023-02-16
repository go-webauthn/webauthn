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

// Config is used to configure the WebAuthn provider.
type Config struct {
	RPDisplayName string
	RPID          string
	RPOrigins     []string
	RPIcon        string

	// AttestationPreference is the default attestation preference when registering credentials.
	AttestationPreference protocol.ConveyancePreference

	// AuthenticatorSelection is the default authenticator selection for both logins and credential registrations.
	AuthenticatorSelection protocol.AuthenticatorSelection

	StringEncodeUserID bool

	Timeout int
	Debug   bool

	// Deprecated: Use RPOrigins instead.
	RPOrigin string
}

// Validate that the config flags in Config are properly set.
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

	return nil
}

// New creates a new WebAuthn object given a valid Config.
func New(config *Config) (webauthn *WebAuthn, err error) {
	if err = config.validate(); err != nil {
		return nil, fmt.Errorf("configuration error: %w", err)
	}

	return &WebAuthn{
		config,
	}, nil
}
