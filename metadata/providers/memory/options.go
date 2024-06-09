package memory

import (
	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
)

// Option describes an optional pattern for this provider.
type Option func(provider *Provider) (err error)

// WithMetadata provides the required metadata for the memory provider.
func WithMetadata(mds map[uuid.UUID]*metadata.MetadataBLOBPayloadEntry) Option {
	return func(provider *Provider) (err error) {
		provider.mds = mds

		return nil
	}
}

// WithValidateEntry requires that the provided metadata has an entry for the given authenticator to be considered
// valid. By default an AAGUID which has a zero value should fail validation if WithValidateEntryPermitZeroAAGUID is not
// provided with the value of true.
func WithValidateEntry(require bool) Option {
	return func(provider *Provider) (err error) {
		provider.entry = require

		return nil
	}
}

// WithValidateEntryPermitZeroAAGUID is an option that permits a zero'd AAGUID from an attestation statement to
// automatically pass metadata validations. Generally helpful to use with WithValidateEntry.
func WithValidateEntryPermitZeroAAGUID(permit bool) Option {
	return func(provider *Provider) (err error) {
		provider.entryPermitZero = permit

		return nil
	}
}

// WithValidateTrustAnchor when set to true enables the validation of the attestation statement against the trust anchor
// from the metadata.
func WithValidateTrustAnchor(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.anchors = validate

		return nil
	}
}

// WithValidateStatus when set to true enables the validation of the attestation statments AAGUID against the desired
// and undesired metadata.AuthenticatorStatus lists.
func WithValidateStatus(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.status = validate

		return nil
	}
}

// WithStatusUndesired provides the list of statuses which are considered undesirable for status report validation
// purposes. Should be used with WithValidateStatus set to true.
func WithStatusUndesired(statuses []metadata.AuthenticatorStatus) Option {
	return func(provider *Provider) (err error) {
		provider.undesired = statuses

		return nil
	}
}

// WithStatusDesired provides the list of statuses which are considered desired and will be required for status report
// validation purposes. Should be used with WithValidateStatus set to true.
func WithStatusDesired(statuses []metadata.AuthenticatorStatus) Option {
	return func(provider *Provider) (err error) {
		provider.desired = statuses

		return nil
	}
}
