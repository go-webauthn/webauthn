package protocol

import (
	"context"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated for the RFC5280 method 1 key identifier.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/hex"
	"fmt"
	"slices"
	"sort"
	"strings"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// ValidateMetadata validates the metadata for the given authenticator.
//
// This is equivalent to [ValidateMetadataWithAuthenticatorData] without the authenticator data, so the validations
// which require it are not performed.
func ValidateMetadata(ctx context.Context, mds metadata.Provider, aaguid uuid.UUID, attestationType, attestationFormat string, x5cs []any) (protoErr *Error) {
	return ValidateMetadataWithAuthenticatorData(ctx, mds, aaguid, attestationType, attestationFormat, x5cs, nil)
}

// ValidateMetadataWithAuthenticatorData validates the metadata for the given authenticator. If the provider implements
// the [metadata.ExtendedProvider] the additional validations it enables are performed, and the authData is required for
// the validations of the flags, credential public key, and extension outputs. When authData is nil those validations
// are not performed.
//
//nolint:gocyclo
func ValidateMetadataWithAuthenticatorData(ctx context.Context, mds metadata.Provider, aaguid uuid.UUID, attestationType, attestationFormat string, x5cs []any, authData *AuthenticatorData) (protoErr *Error) {
	if mds == nil {
		return nil
	}

	if AttestationFormat(attestationFormat) == AttestationFormatNone {
		return nil
	}

	extended, _ := mds.(metadata.ExtendedProvider)

	var (
		entry *metadata.Entry
		certs []*x509.Certificate
		err   error
	)

	// The trust path is only parsed when a validation requires it, so a malformed trust path is only rejected when it
	// would be used.
	parsed := false

	parse := func() (protoErr *Error) {
		if parsed {
			return nil
		}

		parsed = true

		certs, protoErr = metadataParseX5C(aaguid, x5cs)

		return protoErr
	}

	if entry, err = mds.GetEntry(ctx, aaguid); err != nil {
		return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred retrieving the metadata entry: %+v", aaguid, err))
	}

	if entry == nil && aaguid == uuid.Nil && len(x5cs) != 0 && extended != nil && extended.GetValidateEntryKeyIdentifier(ctx) {
		if protoErr = parse(); protoErr != nil {
			return protoErr
		}

		for _, keyIdentifier := range metadataKeyIdentifiers(certs[0]) {
			if entry, err = extended.GetEntryByKeyIdentifier(ctx, keyIdentifier); err != nil {
				return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Attestation Certificate Key Identifier '%s'. Error occurred retrieving the metadata entry: %+v", keyIdentifier, err))
			}

			if entry != nil {
				break
			}
		}
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

	if attestationType != "" && attestationType != stmtTypNone && mds.GetValidateAttestationTypes(ctx) {
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
		reports := entry.StatusReports

		if len(x5cs) != 0 && extended != nil && extended.GetValidateStatusCertificateScope(ctx) {
			if protoErr = parse(); protoErr != nil {
				return protoErr
			}

			reports = metadataStatusReportsInScope(reports, certs)
		}

		if err = mds.ValidateStatusReports(ctx, reports); err != nil {
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred validating the authenticator status: %+v", aaguid, err))
		}
	}

	if mds.GetValidateTrustAnchor(ctx) && len(x5cs) != 0 {
		if protoErr = parse(); protoErr != nil {
			return protoErr
		}

		x5c, x5cis := certs[0], certs[1:]

		// Only the Attestation Identity Key of the TPM format requires preparation, other formats such as FIDO U2F may
		// also convey AttCA but their attestation certificates carry no TPM Subject Alternative Name.
		if attestationType == string(metadata.AttCA) && AttestationFormat(attestationFormat) == AttestationFormatTPM {
			if x5c, x5cis, protoErr = tpmParseAIKAttCA(x5c, x5cis); protoErr != nil {
				return ErrMetadata.WithDetails(protoErr.Details).WithInfo(protoErr.DevInfo).WithError(protoErr)
			}
		}

		if x5c != nil {
			if !entry.MetadataStatement.AttestationTypes.HasBasicFull() {
				return ErrMetadata.WithDetails(fmt.Sprintf("Failed to validate attestation statement signature during attestation validation for Authenticator Attestation GUID '%s'. Attestation was provided in the full format but the authenticator doesn't support the full attestation format.", aaguid))
			}

			if _, err = x5c.Verify(entry.MetadataStatement.Verifier(x5cis)); err != nil {
				return ErrMetadata.WithDetails(fmt.Sprintf("Failed to validate attestation statement signature during attestation validation for Authenticator Attestation GUID '%s'. The attestation certificate could not be verified due to an error validating the trust chain against the Metadata Service.", aaguid)).WithError(err)
			}
		}
	}

	if extended == nil {
		return nil
	}

	return validateMetadataExtended(ctx, extended, entry, aaguid, attestationFormat, authData)
}

//nolint:gocyclo
func validateMetadataExtended(ctx context.Context, mds metadata.ExtendedProvider, entry *metadata.Entry, aaguid uuid.UUID, attestationFormat string, authData *AuthenticatorData) (protoErr *Error) {
	statement := &entry.MetadataStatement

	if mds.GetValidateAAGUID(ctx) {
		for _, value := range []uuid.UUID{entry.AaGUID, statement.AaGUID, statement.AuthenticatorGetInfo.AaGUID} {
			if value != uuid.Nil && value != aaguid {
				return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The metadata contains the mismatched Authenticator Attestation GUID '%s'.", aaguid, value))
			}
		}
	}

	if mds.GetValidateAttestationFormats(ctx) && AttestationFormat(attestationFormat) != AttestationFormatCompound {
		if formats := statement.AuthenticatorGetInfo.AttestationFormats; len(formats) != 0 && !slices.Contains(formats, attestationFormat) {
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The attestation format '%s' is not known to be used by this authenticator.", aaguid, attestationFormat))
		}

		if statement.ProtocolFamily == metadataProtocolFamilyU2F && AttestationFormat(attestationFormat) != AttestationFormatFIDOUniversalSecondFactor {
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The attestation format '%s' can not be produced by an authenticator with the protocol family '%s'.", aaguid, attestationFormat, statement.ProtocolFamily))
		}
	}

	if authData == nil {
		return nil
	}

	flags := authData.Flags

	if mds.GetValidateBackupEligibility(ctx) {
		switch statement.MultiDeviceCredentialSupport {
		case "", metadata.MultiDeviceCredentialUnsupported:
			if flags.HasBackupEligible() || flags.HasBackupState() {
				return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The credential is backup eligible but the authenticator does not support multi-device credentials.", aaguid))
			}
		}
	}

	if mds.GetValidateAlgorithms(ctx) && flags.HasAttestedCredentialData() && len(authData.AttData.CredentialPublicKey) != 0 {
		var key webauthncose.PublicKeyData

		if err := webauthncbor.Unmarshal(authData.AttData.CredentialPublicKey, &key); err != nil {
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred decoding the credential public key: %+v", aaguid, err)).WithError(err)
		}

		if alg := webauthncose.COSEAlgorithmIdentifier(key.Algorithm); !metadataAlgorithmSupported(statement, alg) {
			return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The credential public key algorithm '%s' is not known to be supported by this authenticator.", aaguid, alg))
		}
	}

	if mds.GetValidateExtensions(ctx) && flags.HasExtensions() && len(authData.ExtData) != 0 {
		if protoErr = metadataValidateExtensions(statement, aaguid, authData.ExtData); protoErr != nil {
			return protoErr
		}
	}

	if mds.GetValidateUserVerification(ctx) && flags.HasUserVerified() && !metadataUserVerificationCapable(statement) {
		return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The user was verified but the authenticator is not known to be capable of user verification.", aaguid))
	}

	return nil
}

func metadataParseX5C(aaguid uuid.UUID, x5cs []any) (certs []*x509.Certificate, protoErr *Error) {
	var (
		parsed *x509.Certificate
		raw    []byte
		ok     bool
		err    error
	)

	for i, x5cAny := range x5cs {
		if raw, ok = x5cAny.([]byte); !ok {
			return nil, ErrMetadata.WithDetails(fmt.Sprintf("Failed to parse attestation certificate from x5c during attestation validation for Authenticator Attestation GUID '%s'.", aaguid)).WithInfo(fmt.Sprintf("The %s certificate in the attestation was type '%T' but '[]byte' was expected", loopOrdinalNumber(i), x5cAny))
		}

		if parsed, err = x509.ParseCertificate(raw); err != nil {
			return nil, ErrMetadata.WithDetails(fmt.Sprintf("Failed to parse attestation certificate from x5c during attestation validation for Authenticator Attestation GUID '%s'.", aaguid)).WithInfo(fmt.Sprintf("Error returned from x509.ParseCertificate: %+v", err)).WithError(err)
		}

		certs = append(certs, parsed)
	}

	return certs, nil
}

// metadataKeyIdentifiers returns the candidate attestation certificate key identifiers for a certificate. The value of
// the Subject Key Identifier extension is preferred, followed by the SHA-1 hash of the subjectPublicKey (RFC5280 §4.2.1.2
// method 1) which is used when the extension is absent.
func metadataKeyIdentifiers(cert *x509.Certificate) (keyIdentifiers []string) {
	if len(cert.SubjectKeyId) != 0 {
		keyIdentifiers = append(keyIdentifiers, hex.EncodeToString(cert.SubjectKeyId))
	}

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}

	if _, err := asn1.Unmarshal(cert.RawSubjectPublicKeyInfo, &spki); err == nil {
		sum := sha1.Sum(spki.PublicKey.Bytes) //nolint:gosec // SHA-1 is mandated for the RFC5280 method 1 key identifier.

		if keyIdentifier := hex.EncodeToString(sum[:]); !slices.Contains(keyIdentifiers, keyIdentifier) {
			keyIdentifiers = append(keyIdentifiers, keyIdentifier)
		}
	}

	return keyIdentifiers
}

// metadataStatusReportsInScope returns the status reports which apply to the given attestation trust path. A report
// which relates to a specific certificate only applies when that certificate is part of the trust path.
func metadataStatusReportsInScope(reports []metadata.StatusReport, certs []*x509.Certificate) (scoped []metadata.StatusReport) {
	inPath := func(cert *x509.Certificate) bool {
		return slices.ContainsFunc(certs, cert.Equal)
	}

	for _, report := range reports {
		if report.Certificate == nil && report.BatchCertificate == nil {
			scoped = append(scoped, report)

			continue
		}

		if (report.Certificate != nil && inPath(report.Certificate)) || (report.BatchCertificate != nil && inPath(report.BatchCertificate)) {
			scoped = append(scoped, report)
		}
	}

	return scoped
}

// metadataAlgorithmSupported returns true if the algorithm is known to be supported by the authenticator, or if the
// metadata does not describe the supported algorithms well enough to determine otherwise.
func metadataAlgorithmSupported(statement *metadata.Statement, alg webauthncose.COSEAlgorithmIdentifier) bool {
	info, algs := statement.AuthenticatorGetInfo.Algorithms, statement.AuthenticationAlgorithms

	if len(info) == 0 && len(algs) == 0 {
		return true
	}

	alg = metadataPolymorphicAlgorithm(alg)

	for _, param := range info {
		if metadataPolymorphicAlgorithm(param.Alg) == alg {
			return true
		}
	}

	unknown := false

	for _, a := range algs {
		value, ok := a.COSEAlgorithmIdentifier()
		if !ok {
			unknown = true

			continue
		}

		if value == alg {
			return true
		}
	}

	// An algorithm which is not known to this library can't be ruled out as the algorithm of the credential unless
	// the authenticatorGetInfo algorithms, which are COSE algorithm identifiers, describe the supported algorithms.
	return unknown && len(info) == 0
}

// metadataPolymorphicAlgorithm returns the polymorphic COSE algorithm identifier for a fully-specified identifier.
func metadataPolymorphicAlgorithm(alg webauthncose.COSEAlgorithmIdentifier) webauthncose.COSEAlgorithmIdentifier {
	switch alg {
	case webauthncose.AlgESP256:
		return webauthncose.AlgES256
	case webauthncose.AlgESP384:
		return webauthncose.AlgES384
	case webauthncose.AlgESP512:
		return webauthncose.AlgES512
	case webauthncose.AlgEd25519:
		return webauthncose.AlgEdDSA
	default:
		return alg
	}
}

func metadataValidateExtensions(statement *metadata.Statement, aaguid uuid.UUID, data []byte) (protoErr *Error) {
	supported := slices.Clone(statement.AuthenticatorGetInfo.Extensions)

	for _, extension := range statement.SupportedExtensions {
		supported = append(supported, extension.ID)
	}

	if len(supported) == 0 {
		return nil
	}

	var members map[string]any

	if err := webauthncbor.Unmarshal(data, &members); err != nil {
		return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. Error occurred decoding the authenticator extension outputs: %+v", aaguid, err)).WithError(err)
	}

	var unsupported []string

	for identifier := range members {
		if !slices.Contains(supported, identifier) {
			unsupported = append(unsupported, identifier)
		}
	}

	if len(unsupported) != 0 {
		sort.Strings(unsupported)

		return ErrMetadata.WithInfo(fmt.Sprintf("Failed to validate authenticator metadata for Authenticator Attestation GUID '%s'. The authenticator extension outputs '%s' are not known to be supported by this authenticator.", aaguid, strings.Join(unsupported, "', '")))
	}

	return nil
}

// metadataUserVerificationCapable returns true if the authenticator is known to be capable of user verification, or if
// the metadata does not describe the user verification capabilities.
func metadataUserVerificationCapable(statement *metadata.Statement) bool {
	known := false

	for _, combination := range statement.UserVerificationDetails {
		for _, descriptor := range combination {
			known = true

			switch descriptor.UserVerificationMethod {
			case metadataUserVerifyPresenceInternal, metadataUserVerifyNone:
				continue
			default:
				return true
			}
		}
	}

	if options := statement.AuthenticatorGetInfo.Options; len(options) != 0 {
		known = true

		for _, option := range []string{metadataOptionUV, metadataOptionClientPIN} {
			// The presence of the option indicates the capability, the value only indicates if it's configured.
			if _, ok := options[option]; ok {
				return true
			}
		}
	}

	return !known
}

const (
	metadataProtocolFamilyU2F          = "u2f"
	metadataUserVerifyPresenceInternal = "presence_internal"
	metadataUserVerifyNone             = "none"
	metadataOptionUV                   = "uv"
	metadataOptionClientPIN            = "clientPin"
)

func loopOrdinalNumber(n int) string {
	n++

	if n > 9 && n < 20 {
		return fmt.Sprintf("%dth", n)
	}

	switch n % 10 {
	case 1:
		return fmt.Sprintf("%dst", n)
	case 2:
		return fmt.Sprintf("%dnd", n)
	case 3:
		return fmt.Sprintf("%drd", n)
	default:
		return fmt.Sprintf("%dth", n)
	}
}
