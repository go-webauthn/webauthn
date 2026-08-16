package webauthn

import (
	"fmt"
	"time"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol"
)

// New creates a new [WebAuthn] instance from the provided [Config]. The configuration is validated before the
// instance is returned.
func New(config *Config) (*WebAuthn, error) {
	if err := config.validate(); err != nil {
		return nil, fmt.Errorf(errFmtConfigValidate, err)
	}

	return &WebAuthn{
		config,
	}, nil
}

// WebAuthn is the primary interface of this package. It provides methods to begin and finish both registration and
// login ceremonies. Create an instance using [New] and then call the appropriate Begin/Finish methods for your
// use case. See the package documentation for detailed ceremony flows.
type WebAuthn struct {
	Config *Config
}

// Config represents the Relying Party configuration for WebAuthn operations. At minimum, RPID and RPOrigins must
// be configured. The RPID should be the effective domain of the Relying Party (i.e. "example.com") and RPOrigins
// should contain the fully qualified origins that are permitted (i.e. "https://example.com").
type Config struct {
	// RPID configures the Relying Party Server ID. This should generally be the origin without a scheme and port.
	RPID string

	// RPDisplayName configures the display name for the Relying Party Server. This can be any string.
	RPDisplayName string

	// RPOrigins configures the list of Relying Party Server Origins that are permitted. The provided origins can either
	// be fully qualified origins or strings for simple string comparison. The strings are matched using canonical
	// origin matching semantics, specifically if they start with 'http://' or 'https://' if the provided origin has a
	// case-insensitive equal scheme and host component, they are equal, otherwise simple string comparison is utilized
	// to determine equality.
	//
	// See Also: [RPOpaqueOrigins].
	RPOrigins []string

	// RPOpaqueOrigins configures the list of opaque Relying Party Server Origins that are permitted, i.e. those for
	// which [protocol.IsOpaqueOrigin] returns true because they are not an absolute http or https URL with a host
	// (i.e. "android:apk-key-hash:..."). These are matched by simple string comparison, i.e. as an exact
	// case-sensitive match and never with the scheme and host semantics [Config.RPOrigins] is matched with, they are
	// never matched against the Top Origin of a cross-origin ceremony, and they are never declared in the Related
	// Origin Requests document returned by [WebAuthn.RelatedOrigins].
	//
	// Each value must be one of the forms a client conveys for a native application, a browser extension, or a
	// document loaded from the local file system, i.e. it must carry one of the prefixes of
	// [protocol.OpaqueOriginPrefixes] and a value after it, or be one of those prefixes which is a complete origin in
	// itself such as 'file://'; see [protocol.IsKnownOpaqueOrigin]. Any other value is rejected by validation as it
	// could never match a ceremony.
	//
	// An opaque origin is only conveyed in the response of a ceremony, so it is never a value a ceremony can be bound
	// to with [WithRegistrationOrigin] or [WithLoginOrigin]; the origins configured here stay acceptable while a
	// ceremony is bound to one of [Config.RPOrigins].
	//
	// Configuring this field constrains the other origin fields to what a Related Origin Requests document can
	// express, so that the origins a client resolves and the origins this Relying Party accepts cannot drift apart:
	// [Config.RPOrigins] and [Config.RPTopOrigins] must then hold only non-opaque origins, and [Config.RPOrigins]
	// must carry no more than [protocol.MaximumRelatedOriginLabels] distinct registrable domain labels.
	RPOpaqueOrigins []string

	// RPTopOrigins configures the list of Relying Party Server Top Origins that are permitted. The provided origins can
	// either be fully qualified origins or strings for simple string comparison. The strings are matched using
	// canonical origin matching semantics specifically if they start with 'http://' or 'https://' if the provided
	// origin has a case-insensitive equal scheme and host component they are equal, otherwise simple string comparison
	// is utilized to determine equality.
	//
	// See Also: [RPOpaqueOrigins].
	RPTopOrigins []string

	// RPTopOriginVerificationMode determines the verification mode for the Top Origin value used in cross-origin
	// ceremonies. When the zero value ([protocol.TopOriginDefaultVerificationMode]) is provided, the config
	// validator coerces this field to [protocol.TopOriginExplicitVerificationMode]; i.e. any Top Origin supplied
	// by the client must appear in [Config.RPTopOrigins]. Set this field explicitly to
	// [protocol.TopOriginAutoVerificationMode] or [protocol.TopOriginImplicitVerificationMode] if you need
	// different matching semantics; there is no longer a mode that disables verification entirely.
	RPTopOriginVerificationMode protocol.TopOriginVerificationMode

	// RPAllowCrossOrigin determines whether the RP is allowed to be used in cross-origin contexts. This is disabled
	// by default.
	RPAllowCrossOrigin bool

	// AttestationPreference sets the default attestation conveyance preferences.
	AttestationPreference protocol.ConveyancePreference

	// AuthenticatorSelection sets the default authenticator selection options.
	AuthenticatorSelection protocol.AuthenticatorSelection

	// Debug enables various debug options.
	Debug bool

	// EncodeUserIDAsString ensures the user.id value during registrations is encoded as a raw UTF8 string. This is
	// useful when you only use printable ASCII characters for the random user.id but the browser library does not
	// decode the URL Safe Base64 data.
	//
	// The resulting options are not the PublicKeyCredentialCreationOptionsJSON form, which requires user.id to be a
	// Base64URLString, so a client which passes them to PublicKeyCredential.parseCreationOptionsFromJSON() does one
	// of two things with them, neither of them what the Relying Party intended:
	//
	//   - A value outside the base64url alphabet, such as "alice@example.com", fails to decode and the call throws.
	//     So does one whose length is one more than a multiple of four, such as "a" or "alice", since that is not a
	//     length any base64 encoding produces.
	//   - A value which happens to be valid base64url is accepted and decoded into unrelated bytes. "user123" is
	//     one such value, and arrives at the authenticator as the five bytes ba c7 ab d7 6d, so the user handle
	//     stored against the credential is not the one that was sent.
	//
	// The second outcome is the dangerous one, since nothing reports it. Enable this only for a client which does
	// its own decoding, which is the situation it exists for.
	//
	// Specification: §5.1.8. Deserialize Registration Ceremony Options (https://www.w3.org/TR/webauthn-3/#sctn-parseCreationOptionsFromJSON)
	EncodeUserIDAsString bool

	// Timeouts configures various timeouts.
	Timeouts TimeoutsConfig

	// MDS configures a FIDO Metadata Service provider for authenticator trust validation. When set, the library
	// validates attestation statements against known authenticator metadata including trust anchors, attestation
	// types, and authenticator status. Use the providers in [github.com/go-webauthn/webauthn/metadata/providers/memory]
	// or [github.com/go-webauthn/webauthn/metadata/providers/cached] to create a provider instance.
	MDS metadata.Provider

	// Attestation configures Relying Party policy for the verification of attestation statements. These are the
	// decisions §8 of the specification delegates to the Relying Party rather than fixing. The zero value selects
	// the most restrictive behavior available for each policy it carries.
	Attestation protocol.AttestationPolicy

	// Signature configures Relying Party policy for the verification of signatures. It applies to the attestation
	// signature of a registration and the assertion signature of an authentication alike. The zero value selects
	// the behavior the specification requires.
	Signature protocol.SignaturePolicy

	// Filtering configures the filtering of authenticators based on their AAGUIDs. This is useful for enforcing
	// policy on the authenticators that are available to be registered with the Relying Party.
	Filtering *FilteringConfig

	// ExtensionsUnsolicitedOutputPolicy determines how a client extension output that was not requested by this
	// Relying Party is handled during the finish step of a ceremony. The zero value
	// ([protocol.UnsolicitedOutputPolicyReject]) fails the ceremony, which is the recommended setting. Set
	// [protocol.UnsolicitedOutputPolicyIgnore] only if a client in your deployment is known to return extension
	// outputs unprompted.
	//
	// A Relying Party which reconstructs [SessionData] by hand, rather than persisting the value returned by the
	// Begin* functions verbatim, will lose the record of which extensions were requested and see legitimate
	// outputs rejected.
	ExtensionsUnsolicitedOutputPolicy protocol.UnsolicitedOutputPolicy

	validated bool
}

// FilteringConfig configures the filtering of authenticators based on their AAGUIDs. This is useful for enforcing
// policy on the authenticators that are available to be registered with the Relying Party.
type FilteringConfig struct {
	// ProhibitBackupEligibility if set will prohibit the use of authenticators with the backup eligible flag set.
	ProhibitBackupEligibility bool

	// PermittedAAGUIDs if set is used to filter authenticators by their AAGUID only allowing specific values. This
	// option is mutually exclusive with ProhibitedAAGUIDs and will never exclude a zero AAGUID. To prohibit the use
	// of Zero AAGUIDs, use [Config.MDS] or [FilteringConfig.ProhibitedAAGUIDs].
	PermittedAAGUIDs []uuid.UUID

	// ProhibitedAAGUIDs if set is used to filter authenticators by their AAGUID only prohibiting specific values. This
	// option is mutually exclusive with PermittedAAGUIDs.
	ProhibitedAAGUIDs []uuid.UUID
}

// TimeoutsConfig configures the timeout durations for both login and registration ceremonies. These values are sent
// to the client as the timeout field in the credential request/creation options and optionally enforced server-side.
type TimeoutsConfig struct {
	Login        TimeoutConfig
	Registration TimeoutConfig
}

// TimeoutConfig configures timeout behavior for a specific WebAuthn ceremony (registration or login).
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

// Validate that the config flags in Config are properly set.
func (config *Config) validate() (err error) {
	if config.validated {
		return nil
	}

	if len(config.RPID) != 0 {
		if err = protocol.ValidateRPID(config.RPID); err != nil {
			return fmt.Errorf(errFmtFieldNotValidDomainString, "RPID", err)
		}
	}

	defaultTimeoutConfig := defaultTimeout
	defaultTimeoutUVDConfig := defaultTimeoutUVD

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

	if len(config.RPOrigins) == 0 {
		return fmt.Errorf("must provide at least one value to the 'RPOrigins' field")
	}

	if err = config.validateOpaqueOrigins(); err != nil {
		return err
	}

	if config.RPTopOriginVerificationMode == protocol.TopOriginDefaultVerificationMode {
		config.RPTopOriginVerificationMode = protocol.TopOriginExplicitVerificationMode
	}

	config.validateAttestationPolicy()

	if config.Filtering != nil {
		if len(config.Filtering.PermittedAAGUIDs) > 0 && len(config.Filtering.ProhibitedAAGUIDs) > 0 {
			return fmt.Errorf("cannot set both 'PermittedAAGUIDs' and 'ProhibitedAAGUIDs' in the filtering config")
		}
	}

	config.validated = true

	return nil
}

// validateOpaqueOrigins enforces the separation [Config.RPOpaqueOrigins] draws between the origins a client resolves
// through a Related Origin Requests document and the origins which can only ever be matched by simple string
// comparison. It is a no op unless that field is populated, so a Relying Party which lists an opaque origin in
// [Config.RPOrigins] keeps the behavior it has always had.
//
// The Top Origins are held to the same standard as the Origins minus the label budget, which applies to the origins
// declared in the document rather than to the origin of a top level browsing context.
//
// Each value is additionally held to the forms a client is known to convey, i.e. [protocol.IsKnownOpaqueOrigin]. An
// opaque origin is only ever matched by simple string comparison against a value configured here, so one no client
// produces could never match a ceremony, and rejecting it names the mistake rather than leaving a ceremony to fail
// with an origin error later.
func (config *Config) validateOpaqueOrigins() (err error) {
	if len(config.RPOpaqueOrigins) == 0 {
		return nil
	}

	for _, origin := range config.RPOpaqueOrigins {
		if !protocol.IsOpaqueOrigin(origin) {
			return fmt.Errorf(errFmtOriginsNotOpaqueValue, origin)
		}

		if !protocol.IsKnownOpaqueOrigin(origin) {
			return fmt.Errorf(errFmtOriginsOpaqueUnknown, joinOpaqueOriginPrefixes(), origin)
		}
	}

	if _, err = protocol.NewRelatedOrigins(config.RPOrigins...); err != nil {
		return fmt.Errorf(errFmtOriginsNotRelated, "RPOrigins", err)
	}

	for _, origin := range config.RPTopOrigins {
		if protocol.IsOpaqueOrigin(origin) {
			return fmt.Errorf(errFmtOriginsNotRelatedValue, "RPTopOrigins", origin)
		}
	}

	return nil
}

// validateAttestationPolicy rewrites each zero value of the verification policies to the explicit constant it
// evaluates as, so a Relying Party can tell an unset field apart from a deliberate choice of the same behavior.
// Every default is the most restrictive behavior the policy offers, which for the encoding of a signature is the
// one the specification requires.
func (config *Config) validateAttestationPolicy() {
	if config.Attestation.AndroidKey.AuthorizationScope == protocol.AndroidKeyAuthorizationScopeDefault {
		config.Attestation.AndroidKey.AuthorizationScope = protocol.AndroidKeyAuthorizationScopeTEEEnforced
	}

	if config.Attestation.Compound.SubStatementScope == protocol.CompoundSubStatementScopeDefault {
		config.Attestation.Compound.SubStatementScope = protocol.CompoundSubStatementScopeAll
	}

	if config.Signature.ECDSAEncoding == protocol.ECDSASignatureEncodingDefault {
		config.Signature.ECDSAEncoding = protocol.ECDSASignatureEncodingDER
	}
}

// GetRPID returns the configured Relying Party ID.
func (c *Config) GetRPID() string {
	return c.RPID
}

// GetOrigins returns the configured Relying Party Origins.
func (c *Config) GetOrigins() []string {
	return c.RPOrigins
}

// GetOpaqueOrigins returns the configured opaque Relying Party Origins.
func (c *Config) GetOpaqueOrigins() []string {
	return c.RPOpaqueOrigins
}

// GetTopOrigins returns the configured Relying Party Top Origins.
func (c *Config) GetTopOrigins() []string {
	return c.RPTopOrigins
}

// GetTopOriginVerificationMode returns the configured Top Origin verification mode.
func (c *Config) GetTopOriginVerificationMode() protocol.TopOriginVerificationMode {
	return c.RPTopOriginVerificationMode
}

// GetMetaDataProvider returns the configured FIDO Metadata Service provider.
func (c *Config) GetMetaDataProvider() metadata.Provider {
	return c.MDS
}

// GetAttestationPolicy returns the configured attestation verification policy.
func (c *Config) GetAttestationPolicy() protocol.AttestationPolicy {
	return c.Attestation
}

// GetSignaturePolicy returns the configured signature verification policy.
func (c *Config) GetSignaturePolicy() protocol.SignaturePolicy {
	return c.Signature
}

// ConfigProvider is an interface that provides access to the WebAuthn [Config] values. This is useful for
// implementations that wish to provide configuration from alternative sources.
type ConfigProvider interface {
	GetRPID() string
	GetOrigins() []string
	GetOpaqueOrigins() []string
	GetTopOrigins() []string
	GetTopOriginVerificationMode() protocol.TopOriginVerificationMode
	GetMetaDataProvider() metadata.Provider
	GetAttestationPolicy() protocol.AttestationPolicy
	GetSignaturePolicy() protocol.SignaturePolicy
}

// User is an interface with the Relying Party's User entry and provides the fields and methods needed for WebAuthn
// registration operations.
type User interface {
	// WebAuthnID provides the user handle of the user account. A user handle is an opaque byte sequence with a maximum
	// size of 64 bytes, and is not meant to be displayed to the user.
	//
	// To ensure secure operation, authentication and authorization decisions MUST be made on the basis of this id
	// member, not the displayName nor name members. See Section 6.1 of [RFC8266].
	//
	// It's recommended this value is completely random and uses the entire 64 bytes.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id)
	WebAuthnID() []byte

	// WebAuthnName provides the name attribute of the user account during registration and is a human-palatable name
	// for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party SHOULD
	// let the user choose this, and SHOULD NOT restrict the choice more than necessary.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity)
	WebAuthnName() string

	// WebAuthnDisplayName provides the name attribute of the user account during registration and is a human-palatable
	// name for the user account, intended only for display. For example, "Alex Müller" or "田中倫". The Relying Party
	// SHOULD let the user choose this, and SHOULD NOT restrict the choice more than necessary.
	//
	// Specification: §5.4.3. User Account Parameters for Credential Generation (https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname)
	WebAuthnDisplayName() string

	// WebAuthnCredentials provides the slice of [Credential] objects owned by the user. This generally should be all
	// the [Credential] objects owned by the user regardless of which flow is being used.
	WebAuthnCredentials() []Credential
}
