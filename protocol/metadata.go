package protocol

import (
	"context"
	"crypto/x509"
	"fmt"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
)

func ValidateMetadata(ctx context.Context, mds metadata.Provider, aaguid uuid.UUID, attestationType string, x5cs []any) (protoErr *Error) {
	if mds == nil {
		return nil
	}

	var (
		entry *metadata.Entry
		err   error
	)

	if entry, err = mds.GetEntry(ctx, aaguid); err != nil {
		return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred retreiving the metadata entry: %+v", aaguid, err))
	}

	if entry == nil {
		if aaguid == uuid.Nil && mds.GetValidateEntryPermitZeroAAGUID(ctx) {
			return nil
		}

		if mds.GetValidateEntry(ctx) {
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The authenticator has no registered metadata.", aaguid))
		}

		return nil
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
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The attestation type '%s' is not known to be used by this authenticator.", aaguid.String(), attestationType))
		}
	}

	if mds.GetValidateStatus(ctx) {
		if err = mds.ValidateStatusReports(ctx, entry.StatusReports); err != nil {
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred validating the authenticator status: %+v", aaguid, err))
		}
	}

	if mds.GetValidateTrustAnchor(ctx) {
		if x5cs == nil {
			return nil
		}

		var (
			x5c  *x509.Certificate
			data []byte
			ok   bool
		)

		if len(x5cs) == 0 {
			return ErrMetadata.WithDetails(fmt.Sprintf("Failed to parse attestation certificate from x5c during attestation validation for Authenticator Attestation GUID '%s'.", aaguid)).WithInfo("The attestation had no certificates")
		}

		if data, ok = x5cs[0].([]byte); !ok {
			return ErrMetadata.WithDetails(fmt.Sprintf("Failed to parse attestation certificate from x5c during attestation validation for Authenticator Attestation GUID '%s'.", aaguid)).WithInfo(fmt.Sprintf("The first certificate in the attestation was type '%T' but '[]byte' was expected", x5cs[0]))
		}

		if x5c, err = x509.ParseCertificate(data); err != nil {
			return ErrMetadata.WithDetails(fmt.Sprintf("Failed to parse attestation certificate from x5c during attestation validation for Authenticator Attestation GUID '%s'.", aaguid)).WithInfo(fmt.Sprintf("Error returned from x509.ParseCertificate: %+v", err))
		}

		if attestationType == string(metadata.AttCA) {
			if err = tpmParseSANExtension(x5c); err != nil {
				return ErrMetadata.WithDetails(fmt.Sprintf("Failed to parse attestation certificate from x5c during attestation validation for Authenticator Attestation GUID '%s'.", aaguid)).WithInfo(fmt.Sprintf("Error returned while parsing the SAN extension for a TPM 2.0 Attestation: %+v", err))
			}
		}

		if x5c.Subject.CommonName != x5c.Issuer.CommonName {
			if !entry.MetadataStatement.AttestationTypes.HasBasicFull() {
				return ErrMetadata.WithDetails(fmt.Sprintf("Failed to validate attestation statement signature during attestation validation for Authenticator Attestation GUID '%s'. Attestation was provided in the full format but the authenticator doesn't support the full attestation format.", aaguid))
			}

			if _, err = x5c.Verify(entry.MetadataStatement.Verifier()); err != nil {
				return ErrMetadata.WithDetails(fmt.Sprintf("Failed to validate attestation statement signature during attestation validation for Authenticator Attestation GUID '%s'. The attestation certificate could not be verified due to an error validating the trust chain agaisnt the Metadata Service.", aaguid))
			}
		}
	}

	return nil
}
