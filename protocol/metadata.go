package protocol

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
)

func ValidateMetadata(ctx context.Context, aaguid uuid.UUID, attestationType string, mds metadata.Provider) (entry *metadata.Entry, protoErr *Error) {
	if mds == nil {
		return nil, nil
	}

	var (
		err error
	)

	if entry, err = mds.GetEntry(ctx, aaguid); err != nil {
		return nil, ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred retreiving the metadata entry: %+v", aaguid, err))
	}

	if entry == nil {
		if aaguid == uuid.Nil && mds.GetValidateEntryPermitZeroAAGUID(ctx) {
			return nil, nil
		}

		if mds.GetValidateEntry(ctx) {
			return nil, ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The authenticator has no registered metadata.", aaguid))
		}

		return nil, nil
	}

	if mds.GetValidateAttestationTypes(ctx) {
		found := false

		for _, atype := range entry.MetadataStatement.AttestationTypes {
			if string(atype) == attestationType {
				found = true

				break
			}
		}

		if !found {
			return entry, ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The attestation type '%s' is not known to be used by this authenticator.", aaguid.String(), attestationType))
		}
	}

	if mds.GetValidateStatus(ctx) {
		if err = mds.ValidateStatusReports(ctx, entry.StatusReports); err != nil {
			return entry, ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred validating the authenticator status: %+v", aaguid, err))
		}
	}

	return entry, nil
}
