package webauthn

import (
	"fmt"
	"net/url"

	"github.com/go-webauthn/webauthn/protocol"
)

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

	Timeout int
	Debug   bool

	// Deprecated: Use RPOrigins instead.
	RPOrigin string

	validated bool
}

// Validate that the config flags in Config are properly set.
func (config *Config) validate() error {
	if config.validated {
		return nil
	}

	if len(config.RPDisplayName) == 0 {
		return fmt.Errorf(errFmtEmptyField, "RPDisplayName")
	}

	if len(config.RPID) == 0 {
		return fmt.Errorf(errFmtEmptyField, "RPID")
	}

	_, err := url.Parse(config.RPID)
	if err != nil {
		return fmt.Errorf("RPID not valid URI: %+v", err)
	}

	if config.Timeout == 0 {
		config.Timeout = defaultTimeout
	}

	if len(config.RPOrigin) > 0 {
		if len(config.RPOrigins) != 0 {
			return fmt.Errorf("deprecated field 'RPOrigin' can't be defined at the same tme as the replacement field 'RPOrigins'")
		}

		config.RPOrigins = []string{config.RPOrigin}
	}

	if len(config.RPOrigins) == 0 {
		return fmt.Errorf("must provide at least one value to the 'RPOrigins' field")
	}

	if config.AuthenticatorSelection.RequireResidentKey == nil {
		config.AuthenticatorSelection.RequireResidentKey = protocol.ResidentKeyNotRequired()
	}

	if config.AuthenticatorSelection.UserVerification == "" {
		config.AuthenticatorSelection.UserVerification = protocol.VerificationPreferred
	}

	config.validated = true

	return nil
}

// New creates a new WebAuthn object given a valid Config.
func New(config *Config) (webauthn *WebAuthn, err error) {
	if err = config.validate(); err != nil {
		return nil, fmt.Errorf(errFmtConfigValidate, err)
	}

	return &WebAuthn{
		config,
	}, nil
}
