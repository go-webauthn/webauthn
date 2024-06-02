package memory

import (
	"context"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
)

// New returns a new memory provider given a map, list of undesired AuthenticatorStatus types, a
// required boolean which if true will cause registrations to fail if no metadata entry is found for the attestation
// statement, and a validate boolean which determines if trust anchors should be validated by this provider during
// registration.
//
// If the undesired status slice is nil it will use a default value. You must explicitly use an empty slice to disable
// this functionality.
func New(mds map[uuid.UUID]*metadata.MetadataBLOBPayloadEntry, undesired []metadata.AuthenticatorStatus, required, validate bool) *Provider {
	if undesired == nil {
		undesired = make([]metadata.AuthenticatorStatus, len(defaultUndesiredAuthenticatorStatus))

		for i := range defaultUndesiredAuthenticatorStatus {
			undesired[i] = defaultUndesiredAuthenticatorStatus[i]
		}
	}

	return &Provider{
		mds:       mds,
		undesired: undesired,
		require:   required,
		validate:  validate,
	}
}

type Provider struct {
	mds       map[uuid.UUID]*metadata.MetadataBLOBPayloadEntry
	desired   []metadata.AuthenticatorStatus
	undesired []metadata.AuthenticatorStatus
	require   bool
	validate  bool
	status    bool
}

func (p *Provider) GetTrustAnchorValidation(ctx context.Context) (validate bool) {
	return p.validate
}

func (p *Provider) GetAuthenticatorStatusValidation(ctx context.Context) (validate bool) {
	return len(p.undesired) > 0
}

func (p *Provider) GetRequireEntry(ctx context.Context) (require bool) {
	return p.require
}

func (p *Provider) GetEntry(ctx context.Context, aaguid uuid.UUID) (entry *metadata.MetadataBLOBPayloadEntry, err error) {
	if p.mds == nil {
		return nil, metadata.ErrNotInitialized
	}

	var ok bool

	if entry, ok = p.mds[aaguid]; ok {
		return entry, nil
	}

	return nil, nil
}

func (p *Provider) ValidateAuthenticatorStatusReports(ctx context.Context, reports []metadata.StatusReport) (err error) {
	if !p.status {
		return nil
	}

	return metadata.ValidateStatusReports(reports, p.desired, p.undesired)
}

func (p *Provider) GetAuthenticatorStatusIsUndesired(ctx context.Context, status metadata.AuthenticatorStatus) (undesired bool) {
	for _, s := range p.undesired {
		if s == status {
			return true
		}
	}

	return false
}
