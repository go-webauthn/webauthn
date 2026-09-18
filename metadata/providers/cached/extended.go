package cached

import (
	"context"

	"github.com/go-webauthn/webauthn/metadata"
)

// GetEntryByKeyIdentifier forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetEntryByKeyIdentifier(ctx context.Context, keyIdentifier string) (entry *metadata.Entry, err error) {
	if extended, ok := p.Provider.(metadata.ExtendedProvider); ok {
		return extended.GetEntryByKeyIdentifier(ctx, keyIdentifier)
	}

	return nil, nil
}

// GetValidateEntryKeyIdentifier forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetValidateEntryKeyIdentifier(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateEntryKeyIdentifier)
}

// GetValidateStatusCertificateScope forwards to the underlying provider if it implements the
// [metadata.ExtendedProvider].
func (p *Provider) GetValidateStatusCertificateScope(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateStatusCertificateScope)
}

// GetValidateAAGUID forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetValidateAAGUID(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateAAGUID)
}

// GetValidateAttestationFormats forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetValidateAttestationFormats(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateAttestationFormats)
}

// GetValidateAlgorithms forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetValidateAlgorithms(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateAlgorithms)
}

// GetValidateBackupEligibility forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetValidateBackupEligibility(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateBackupEligibility)
}

// GetValidateExtensions forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetValidateExtensions(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateExtensions)
}

// GetValidateUserVerification forwards to the underlying provider if it implements the [metadata.ExtendedProvider].
func (p *Provider) GetValidateUserVerification(ctx context.Context) (validate bool) {
	return p.extended(ctx, metadata.ExtendedProvider.GetValidateUserVerification)
}

func (p *Provider) extended(ctx context.Context, fn func(metadata.ExtendedProvider, context.Context) bool) (validate bool) {
	if extended, ok := p.Provider.(metadata.ExtendedProvider); ok {
		return fn(extended, ctx)
	}

	return false
}

var (
	_ metadata.ExtendedProvider = (*Provider)(nil)
)
