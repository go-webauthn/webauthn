package metadata

import (
	"context"

	"github.com/google/uuid"
)

// NewMemoryProvider returns a new memory provider given a map, list of undesired AuthenticatorStatus types, a
// required boolean which if true will cause registrations to fail if no metadata entry is found for the attestation
// statement, and a validate boolean which determines if trust anchors should be validated by this provider during
// registration.
//
// If the undesired status slice is nil it will use a default value. You must explicitly use an empty slice to disable
// this functionality.
func NewMemoryProvider(mds map[uuid.UUID]*MetadataBLOBPayloadEntry, undesired []AuthenticatorStatus, required, validate bool) *MemoryProvider {
	if undesired == nil {
		undesired = make([]AuthenticatorStatus, len(defaultUndesiredAuthenticatorStatus))

		for i := range defaultUndesiredAuthenticatorStatus {
			undesired[i] = defaultUndesiredAuthenticatorStatus[i]
		}
	}

	return &MemoryProvider{
		mds:       mds,
		undesired: undesired,
		require:   required,
		validate:  validate,
	}
}

type MemoryProvider struct {
	mds       map[uuid.UUID]*MetadataBLOBPayloadEntry
	undesired []AuthenticatorStatus
	require   bool
	validate  bool
}

func (p *MemoryProvider) GetTrustAnchorValidation(ctx context.Context) (validate bool) {
	return p.validate
}

func (p *MemoryProvider) GetAuthenticatorStatusValidation(ctx context.Context) (validate bool) {
	return len(p.undesired) > 0
}

func (p *MemoryProvider) GetRequireEntry(ctx context.Context) (require bool) {
	return p.require
}

func (p *MemoryProvider) GetEntry(ctx context.Context, aaguid uuid.UUID) (entry *MetadataBLOBPayloadEntry, err error) {
	if p.mds == nil {
		return nil, ErrNotInitialized
	}

	var ok bool

	if entry, ok = p.mds[aaguid]; ok {
		return entry, nil
	}

	return nil, nil
}

func (p *MemoryProvider) GetAuthenticatorStatusIsUndesired(ctx context.Context, status AuthenticatorStatus) (undesired bool) {
	for _, s := range p.undesired {
		if s == status {
			return true
		}
	}

	return false
}
