package memory

import (
	"strings"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
)

// Option describes an optional pattern for this provider.
type Option func(provider *Provider) (err error)

// WithMetadata provides the required metadata for the memory provider.
func WithMetadata(mds map[uuid.UUID]*metadata.Entry) Option {
	return func(provider *Provider) (err error) {
		provider.mds = mds

		return nil
	}
}

// WithValidateEntry requires that the provided metadata has an entry for the given authenticator to be considered
// valid. By default an AAGUID which has a zero value should fail validation if [WithValidateEntryPermitZeroAAGUID] is not
// provided with the value of true. Default is true.
func WithValidateEntry(require bool) Option {
	return func(provider *Provider) (err error) {
		provider.entry = require

		return nil
	}
}

// WithValidateEntryPermitZeroAAGUID is an option that permits a zero'd AAGUID from an attestation statement to
// automatically pass metadata validations. Generally helpful to use with [WithValidateEntry]. Default is false.
func WithValidateEntryPermitZeroAAGUID(permit bool) Option {
	return func(provider *Provider) (err error) {
		provider.entryPermitZero = permit

		return nil
	}
}

// WithValidateTrustAnchor when set to true enables the validation of the attestation statement against the trust anchor
// from the metadata. Default is true.
func WithValidateTrustAnchor(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.anchors = validate

		return nil
	}
}

// WithValidateStatus when set to true enables the validation of the attestation statements AAGUID against the desired
// and undesired [metadata.AuthenticatorStatus] lists. Default is true.
func WithValidateStatus(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.status = validate

		return nil
	}
}

// WithValidateAttestationTypes when set to true enables the validation of the attestation statements type against the
// known types the authenticator can produce. Default is true.
func WithValidateAttestationTypes(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.attestation = validate

		return nil
	}
}

// WithStatusUndesired provides the list of statuses which are considered undesirable for status report validation
// purposes. Should be used with [WithValidateStatus] set to true.
func WithStatusUndesired(statuses []metadata.AuthenticatorStatus) Option {
	return func(provider *Provider) (err error) {
		provider.undesired = statuses

		return nil
	}
}

// WithStatusDesired provides the list of statuses which are considered desired and will be required for status report
// validation purposes. Should be used with [WithValidateStatus] set to true.
func WithStatusDesired(statuses []metadata.AuthenticatorStatus) Option {
	return func(provider *Provider) (err error) {
		provider.desired = statuses

		return nil
	}
}

// WithMetadataKeyIdentifiers provides the metadata indexed by the attestation certificate key identifiers, which is
// used to look up entries for authenticators without an AAGUID such as FIDO U2F authenticators. Should be used with
// [WithValidateEntryKeyIdentifier] set to true. See [metadata.Metadata.ToKeyIdentifierMap].
func WithMetadataKeyIdentifiers(mds map[string]*metadata.Entry) Option {
	return func(provider *Provider) (err error) {
		provider.mdsKeyIDs = make(map[string]*metadata.Entry, len(mds))

		for keyIdentifier, entry := range mds {
			provider.mdsKeyIDs[strings.ToLower(keyIdentifier)] = entry
		}

		return nil
	}
}

// WithValidateEntryKeyIdentifier when set to true enables looking up the entry for an attestation statement with a zero
// AAGUID using the key identifier of the attestation certificate. The entry is then subject to the same validations as
// an entry looked up by AAGUID. Should be used with [WithMetadataKeyIdentifiers]. Default is false.
func WithValidateEntryKeyIdentifier(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.entryKeyID = validate

		return nil
	}
}

// WithValidateStatusCertificateScope when set to true only considers status reports which relate to a specific
// certificate when that certificate is part of the attestation trust path, i.e. a compromise of one batch of
// authenticators does not affect other batches of the same model. Default is false.
func WithValidateStatusCertificateScope(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.statusScope = validate

		return nil
	}
}

// WithValidateAAGUID when set to true enables the validation that the AAGUID values present in the metadata entry,
// metadata statement, and authenticatorGetInfo match the AAGUID of the authenticator. Default is false.
func WithValidateAAGUID(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.aaguid = validate

		return nil
	}
}

// WithValidateAttestationFormats when set to true enables the validation of the attestation statement format against
// the formats the authenticator is known to produce. Default is false.
func WithValidateAttestationFormats(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.formats = validate

		return nil
	}
}

// WithValidateAlgorithms when set to true enables the validation of the credential public key algorithm against the
// algorithms the authenticator is known to support. Default is false.
func WithValidateAlgorithms(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.algorithms = validate

		return nil
	}
}

// WithValidateBackupEligibility when set to true enables the validation of the Backup Eligibility and Backup State
// flags against the multi-device credential support of the authenticator. Default is false.
func WithValidateBackupEligibility(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.backup = validate

		return nil
	}
}

// WithValidateExtensions when set to true enables the validation of the authenticator extension outputs against the
// extensions the authenticator is known to support. Default is false.
func WithValidateExtensions(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.extensions = validate

		return nil
	}
}

// WithValidateUserVerification when set to true enables the validation that the User Verified flag is only set when
// the authenticator is known to be capable of user verification. Default is false.
func WithValidateUserVerification(validate bool) Option {
	return func(provider *Provider) (err error) {
		provider.uv = validate

		return nil
	}
}
