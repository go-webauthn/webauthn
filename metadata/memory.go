package metadata

import (
	"context"

	"github.com/google/uuid"
)

// NewMemoryProvider returns a new memory provider given a map, list of undesired AuthenticatorStatus types, and a
// conformance requirement boolean.
//
// If the undesired status slice is nil it will use a default value. You must explicitly use an empty slice to disable
// this functionality.
func NewMemoryProvider(mds map[uuid.UUID]*MetadataBLOBPayloadEntry, undesired []AuthenticatorStatus, required bool) *MemoryProvider {
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
	}
}

type MemoryProvider struct {
	mds       map[uuid.UUID]*MetadataBLOBPayloadEntry
	undesired []AuthenticatorStatus
	require   bool
}

func (p *MemoryProvider) GetRequireConformance(ctx context.Context) (require bool) {
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

func (p *MemoryProvider) GetIsUndesiredAuthenticatorStatus(ctx context.Context, status AuthenticatorStatus) (isUndesiredAuthenticatorStatus bool) {
	for _, s := range p.undesired {
		if s == status {
			return true
		}
	}

	return false
}
