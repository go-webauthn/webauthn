package memory

import (
	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
)

type Opt func(*Provider)

func WithMetadata(metadata map[uuid.UUID]*metadata.MetadataBLOBPayloadEntry) Opt {
	return func(provider *Provider) {
		provider.mds = metadata
	}
}
