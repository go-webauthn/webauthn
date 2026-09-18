package protocol

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha1" //nolint:gosec // SHA-1 is mandated for the RFC5280 method 1 key identifier.
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/testing/mocks"
)

func TestValidateMetadataExtended(t *testing.T) {
	aaguid := uuid.MustParse("0865c31d-05dc-4fb1-adce-3227bfb19967")
	other := uuid.MustParse("7e3f3d30-3557-4442-bdae-139312178b39")

	es256 := metadataTestCredentialPublicKey(t, webauthncose.AlgES256)
	esp256 := metadataTestCredentialPublicKey(t, webauthncose.AlgESP256)
	credProtect := metadataTestExtensions(t, map[string]any{"credProtect": 2})

	attested := func(key []byte, flags AuthenticatorFlags) *AuthenticatorData {
		return &AuthenticatorData{Flags: FlagAttestedCredentialData | flags, AttData: AttestedCredentialData{CredentialPublicKey: key}}
	}

	testCases := []struct {
		name      string
		statement metadata.Statement
		opts      []memory.Option
		format    string
		authData  *AuthenticatorData
		err       string
	}{
		{
			name:      "ShouldNotValidateWhenTogglesAreDisabled",
			statement: metadata.Statement{AaGUID: other, ProtocolFamily: "u2f", UserVerificationDetails: [][]metadata.VerificationMethodDescriptor{{{UserVerificationMethod: "presence_internal"}}}},
			authData:  attested(es256, FlagBackupEligible|FlagUserVerified),
		},
		{
			name:      "ShouldFailAAGUIDMismatchStatement",
			statement: metadata.Statement{AaGUID: other},
			opts:      []memory.Option{memory.WithValidateAAGUID(true)},
			err:       "The metadata contains the mismatched Authenticator Attestation GUID '7e3f3d30-3557-4442-bdae-139312178b39'.",
		},
		{
			name:      "ShouldFailAAGUIDMismatchAuthenticatorGetInfo",
			statement: metadata.Statement{AaGUID: aaguid, AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{AaGUID: other}},
			opts:      []memory.Option{memory.WithValidateAAGUID(true)},
			err:       "The metadata contains the mismatched Authenticator Attestation GUID '7e3f3d30-3557-4442-bdae-139312178b39'.",
		},
		{
			name:      "ShouldPassAAGUIDMatch",
			statement: metadata.Statement{AaGUID: aaguid, AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{AaGUID: aaguid}},
			opts:      []memory.Option{memory.WithValidateAAGUID(true)},
		},
		{
			name:      "ShouldFailAttestationFormatNotInAuthenticatorGetInfo",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{AttestationFormats: []string{"packed"}}},
			opts:      []memory.Option{memory.WithValidateAttestationFormats(true)},
			format:    "tpm",
			err:       "The attestation format 'tpm' is not known to be used by this authenticator.",
		},
		{
			name:      "ShouldPassAttestationFormatInAuthenticatorGetInfo",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{AttestationFormats: []string{"tpm", "packed"}}},
			opts:      []memory.Option{memory.WithValidateAttestationFormats(true)},
		},
		{
			name:      "ShouldPassAttestationFormatCompound",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{AttestationFormats: []string{"packed"}}},
			opts:      []memory.Option{memory.WithValidateAttestationFormats(true)},
			format:    "compound",
		},
		{
			name:      "ShouldPassAttestationFormatWithoutAuthenticatorGetInfo",
			statement: metadata.Statement{ProtocolFamily: "fido2"},
			opts:      []memory.Option{memory.WithValidateAttestationFormats(true)},
			format:    "tpm",
		},
		{
			name:      "ShouldFailAttestationFormatForU2FProtocolFamily",
			statement: metadata.Statement{ProtocolFamily: "u2f"},
			opts:      []memory.Option{memory.WithValidateAttestationFormats(true)},
			err:       "The attestation format 'packed' can not be produced by an authenticator with the protocol family 'u2f'.",
		},
		{
			name:      "ShouldPassAttestationFormatFIDOU2FForU2FProtocolFamily",
			statement: metadata.Statement{ProtocolFamily: "u2f"},
			opts:      []memory.Option{memory.WithValidateAttestationFormats(true)},
			format:    "fido-u2f",
		},
		{
			name:      "ShouldFailBackupEligibleWhenUnsupported",
			statement: metadata.Statement{MultiDeviceCredentialSupport: metadata.MultiDeviceCredentialUnsupported},
			opts:      []memory.Option{memory.WithValidateBackupEligibility(true)},
			authData:  attested(es256, FlagBackupEligible),
			err:       "The credential is backup eligible but the authenticator does not support multi-device credentials.",
		},
		{
			name:     "ShouldFailBackupStateWhenAbsent",
			opts:     []memory.Option{memory.WithValidateBackupEligibility(true)},
			authData: attested(es256, FlagBackupEligible|FlagBackupState),
			err:      "The credential is backup eligible but the authenticator does not support multi-device credentials.",
		},
		{
			name:     "ShouldPassNotBackupEligibleWhenAbsent",
			opts:     []memory.Option{memory.WithValidateBackupEligibility(true)},
			authData: attested(es256, 0),
		},
		{
			name:      "ShouldPassBackupEligibleWhenExplicit",
			statement: metadata.Statement{MultiDeviceCredentialSupport: metadata.MultiDeviceCredentialExplicit},
			opts:      []memory.Option{memory.WithValidateBackupEligibility(true)},
			authData:  attested(es256, FlagBackupEligible|FlagBackupState),
		},
		{
			name:      "ShouldPassNotBackupEligibleWhenImplicit",
			statement: metadata.Statement{MultiDeviceCredentialSupport: metadata.MultiDeviceCredentialImplicit},
			opts:      []memory.Option{memory.WithValidateBackupEligibility(true)},
			authData:  attested(es256, 0),
		},
		{
			name:      "ShouldPassBackupEligibleWithoutAuthenticatorData",
			statement: metadata.Statement{MultiDeviceCredentialSupport: metadata.MultiDeviceCredentialUnsupported},
			opts:      []memory.Option{memory.WithValidateBackupEligibility(true)},
		},
		{
			name:      "ShouldPassAlgorithmInAuthenticatorGetInfo",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{Algorithms: []metadata.PublicKeyCredentialParameters{{Type: "public-key", Alg: webauthncose.AlgES256}}}},
			opts:      []memory.Option{memory.WithValidateAlgorithms(true)},
			authData:  attested(es256, 0),
		},
		{
			name:      "ShouldPassFullySpecifiedAlgorithmInAuthenticatorGetInfo",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{Algorithms: []metadata.PublicKeyCredentialParameters{{Type: "public-key", Alg: webauthncose.AlgES256}}}},
			opts:      []memory.Option{memory.WithValidateAlgorithms(true)},
			authData:  attested(esp256, 0),
		},
		{
			name:      "ShouldFailAlgorithmNotInAuthenticatorGetInfo",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{Algorithms: []metadata.PublicKeyCredentialParameters{{Type: "public-key", Alg: webauthncose.AlgRS256}}}},
			opts:      []memory.Option{memory.WithValidateAlgorithms(true)},
			authData:  attested(es256, 0),
			err:       "The credential public key algorithm 'ES256' is not known to be supported by this authenticator.",
		},
		{
			name:      "ShouldPassAlgorithmInAuthenticationAlgorithms",
			statement: metadata.Statement{AuthenticationAlgorithms: []metadata.AuthenticationAlgorithm{metadata.ALG_SIGN_SECP256R1_ECDSA_SHA256_RAW}},
			opts:      []memory.Option{memory.WithValidateAlgorithms(true)},
			authData:  attested(es256, 0),
		},
		{
			name:      "ShouldFailAlgorithmNotInAuthenticationAlgorithms",
			statement: metadata.Statement{AuthenticationAlgorithms: []metadata.AuthenticationAlgorithm{metadata.ALG_SIGN_ED25519_EDDSA_SHA512_RAW}},
			opts:      []memory.Option{memory.WithValidateAlgorithms(true)},
			authData:  attested(es256, 0),
			err:       "The credential public key algorithm 'ES256' is not known to be supported by this authenticator.",
		},
		{
			name:      "ShouldPassAlgorithmWithUnknownAuthenticationAlgorithm",
			statement: metadata.Statement{AuthenticationAlgorithms: []metadata.AuthenticationAlgorithm{metadata.ALG_SIGN_ED25519_EDDSA_SHA512_RAW, "sm2_sm3_raw"}},
			opts:      []memory.Option{memory.WithValidateAlgorithms(true)},
			authData:  attested(es256, 0),
		},
		{
			name:     "ShouldPassAlgorithmWithoutMetadataAlgorithms",
			opts:     []memory.Option{memory.WithValidateAlgorithms(true)},
			authData: attested(es256, 0),
		},
		{
			name:      "ShouldPassSupportedExtension",
			statement: metadata.Statement{SupportedExtensions: []metadata.ExtensionDescriptor{{ID: "credProtect"}}},
			opts:      []memory.Option{memory.WithValidateExtensions(true)},
			authData:  &AuthenticatorData{Flags: FlagHasExtensions, ExtData: credProtect},
		},
		{
			name:      "ShouldPassAuthenticatorGetInfoExtension",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{Extensions: []string{"credProtect"}}},
			opts:      []memory.Option{memory.WithValidateExtensions(true)},
			authData:  &AuthenticatorData{Flags: FlagHasExtensions, ExtData: credProtect},
		},
		{
			name:      "ShouldFailUnsupportedExtensions",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{Extensions: []string{"credProtect"}}},
			opts:      []memory.Option{memory.WithValidateExtensions(true)},
			authData:  &AuthenticatorData{Flags: FlagHasExtensions, ExtData: metadataTestExtensions(t, map[string]any{"credProtect": 2, "hmac-secret": true, "credBlob": true})},
			err:       "The authenticator extension outputs 'credBlob', 'hmac-secret' are not known to be supported by this authenticator.",
		},
		{
			name:     "ShouldPassExtensionsWithoutMetadataExtensions",
			opts:     []memory.Option{memory.WithValidateExtensions(true)},
			authData: &AuthenticatorData{Flags: FlagHasExtensions, ExtData: credProtect},
		},
		{
			name:      "ShouldFailUserVerifiedWithPresenceOnly",
			statement: metadata.Statement{UserVerificationDetails: [][]metadata.VerificationMethodDescriptor{{{UserVerificationMethod: "presence_internal"}}}},
			opts:      []memory.Option{memory.WithValidateUserVerification(true)},
			authData:  &AuthenticatorData{Flags: FlagUserPresent | FlagUserVerified},
			err:       "The user was verified but the authenticator is not known to be capable of user verification.",
		},
		{
			name:      "ShouldFailUserVerifiedWithoutAuthenticatorGetInfoOptions",
			statement: metadata.Statement{AuthenticatorGetInfo: metadata.AuthenticatorGetInfo{Options: map[string]bool{"up": true, "rk": false}}},
			opts:      []memory.Option{memory.WithValidateUserVerification(true)},
			authData:  &AuthenticatorData{Flags: FlagUserPresent | FlagUserVerified},
			err:       "The user was verified but the authenticator is not known to be capable of user verification.",
		},
		{
			name:      "ShouldPassUserVerifiedWithFingerprint",
			statement: metadata.Statement{UserVerificationDetails: [][]metadata.VerificationMethodDescriptor{{{UserVerificationMethod: "presence_internal"}}, {{UserVerificationMethod: "fingerprint_internal"}}}},
			opts:      []memory.Option{memory.WithValidateUserVerification(true)},
			authData:  &AuthenticatorData{Flags: FlagUserPresent | FlagUserVerified},
		},
		{
			name: "ShouldPassUserVerifiedWithClientPINOption",
			statement: metadata.Statement{
				UserVerificationDetails: [][]metadata.VerificationMethodDescriptor{{{UserVerificationMethod: "presence_internal"}}},
				AuthenticatorGetInfo:    metadata.AuthenticatorGetInfo{Options: map[string]bool{"clientPin": false}},
			},
			opts:     []memory.Option{memory.WithValidateUserVerification(true)},
			authData: &AuthenticatorData{Flags: FlagUserPresent | FlagUserVerified},
		},
		{
			name:      "ShouldPassUserNotVerifiedWithPresenceOnly",
			statement: metadata.Statement{UserVerificationDetails: [][]metadata.VerificationMethodDescriptor{{{UserVerificationMethod: "presence_internal"}}}},
			opts:      []memory.Option{memory.WithValidateUserVerification(true)},
			authData:  &AuthenticatorData{Flags: FlagUserPresent},
		},
		{
			name:     "ShouldPassUserVerifiedWithoutMetadata",
			opts:     []memory.Option{memory.WithValidateUserVerification(true)},
			authData: &AuthenticatorData{Flags: FlagUserPresent | FlagUserVerified},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			format := tc.format
			if format == "" {
				format = "packed"
			}

			mds := metadataTestExtendedProvider(t, map[uuid.UUID]*metadata.Entry{aaguid: {AaGUID: aaguid, MetadataStatement: tc.statement}}, nil, tc.opts...)

			actual := ValidateMetadataWithAuthenticatorData(context.Background(), mds, aaguid, string(metadata.BasicFull), format, nil, tc.authData)

			if tc.err == "" {
				assert.Nil(t, actual)

				return
			}

			require.NotNil(t, actual)
			assert.Equal(t, ErrMetadata.Type, actual.Type)
			assert.Equal(t, "Failed to validate authenticator metadata for Authenticator Attestation GUID '0865c31d-05dc-4fb1-adce-3227bfb19967'. "+tc.err, actual.DevInfo)
		})
	}
}

func TestValidateMetadataExtendedNotImplemented(t *testing.T) {
	aaguid := uuid.MustParse("0865c31d-05dc-4fb1-adce-3227bfb19967")

	ctrl := gomock.NewController(t)
	mds := mocks.NewMockMetadataProvider(ctrl)

	entry := &metadata.Entry{
		MetadataStatement: metadata.Statement{
			AaGUID:                       uuid.MustParse("7e3f3d30-3557-4442-bdae-139312178b39"),
			ProtocolFamily:               "u2f",
			MultiDeviceCredentialSupport: metadata.MultiDeviceCredentialUnsupported,
			UserVerificationDetails:      [][]metadata.VerificationMethodDescriptor{{{UserVerificationMethod: "presence_internal"}}},
		},
	}

	mds.EXPECT().GetEntry(gomock.Any(), aaguid).Return(entry, nil)
	mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(false)
	mds.EXPECT().GetValidateStatus(gomock.Any()).Return(false)
	mds.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(false)

	authData := &AuthenticatorData{Flags: FlagUserPresent | FlagUserVerified | FlagBackupEligible}

	assert.Nil(t, ValidateMetadataWithAuthenticatorData(context.Background(), mds, aaguid, string(metadata.BasicFull), "packed", nil, authData))
}

func TestValidateMetadataExtendedKeyIdentifier(t *testing.T) {
	root, rootKey := metadataTestGenerateCertificate(t, "Metadata Root", nil, nil)

	// A CA certificate is issued with the Subject Key Identifier extension, and a leaf certificate without it.
	withSKI, _ := metadataTestGenerateCertificate(t, "Attestation", root, rootKey)
	withoutSKI := metadataTestGenerateLeafCertificate(t, root, rootKey)

	require.NotEmpty(t, withSKI.SubjectKeyId)
	require.Empty(t, withoutSKI.SubjectKeyId)

	entry := &metadata.Entry{
		MetadataStatement: metadata.Statement{
			AttestationTypes:            metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
			AttestationRootCertificates: []*x509.Certificate{root},
		},
	}

	testCases := []struct {
		name     string
		cert     *x509.Certificate
		keyID    string
		validate bool
		err      string
	}{
		{
			name:     "ShouldFindEntryBySubjectKeyIdentifier",
			cert:     withSKI,
			keyID:    hex.EncodeToString(withSKI.SubjectKeyId),
			validate: true,
		},
		{
			name:     "ShouldFindEntryBySubjectKeyIdentifierUppercase",
			cert:     withSKI,
			keyID:    strings.ToUpper(hex.EncodeToString(withSKI.SubjectKeyId)),
			validate: true,
		},
		{
			name:     "ShouldFindEntryByPublicKeyHash",
			cert:     withoutSKI,
			keyID:    metadataTestPublicKeyHash(t, withoutSKI),
			validate: true,
		},
		{
			name:     "ShouldNotFindEntryWhenDisabled",
			cert:     withSKI,
			keyID:    hex.EncodeToString(withSKI.SubjectKeyId),
			validate: false,
			err:      "Failed to validate authenticator metadata for Authenticator Attestation GUID '00000000-0000-0000-0000-000000000000'. The authenticator has no registered metadata.",
		},
		{
			name:     "ShouldNotFindEntryForUnknownKeyIdentifier",
			cert:     withSKI,
			keyID:    "00112233445566778899aabbccddeeff00112233",
			validate: true,
			err:      "Failed to validate authenticator metadata for Authenticator Attestation GUID '00000000-0000-0000-0000-000000000000'. The authenticator has no registered metadata.",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			mds := metadataTestExtendedProvider(t, map[uuid.UUID]*metadata.Entry{}, map[string]*metadata.Entry{tc.keyID: entry},
				memory.WithValidateEntry(true),
				memory.WithValidateTrustAnchor(true),
				memory.WithValidateAttestationTypes(true),
				memory.WithValidateEntryKeyIdentifier(tc.validate),
			)

			actual := ValidateMetadata(context.Background(), mds, uuid.Nil, string(metadata.BasicFull), "fido-u2f", []any{tc.cert.Raw})

			if tc.err == "" {
				assert.Nil(t, actual)

				return
			}

			require.NotNil(t, actual)
			assert.Equal(t, tc.err, actual.DevInfo)
		})
	}

	t.Run("ShouldValidateEntryFoundByKeyIdentifier", func(t *testing.T) {
		mds := metadataTestExtendedProvider(t, map[uuid.UUID]*metadata.Entry{}, map[string]*metadata.Entry{hex.EncodeToString(withSKI.SubjectKeyId): entry},
			memory.WithValidateEntry(true),
			memory.WithValidateAttestationTypes(true),
			memory.WithValidateEntryKeyIdentifier(true),
		)

		actual := ValidateMetadata(context.Background(), mds, uuid.Nil, string(metadata.AttCA), "fido-u2f", []any{withSKI.Raw})

		require.NotNil(t, actual)
		assert.Equal(t, "Failed to validate authenticator metadata for Authenticator Attestation GUID '00000000-0000-0000-0000-000000000000'. The attestation type 'attca' is not known to be used by this authenticator.", actual.DevInfo)
	})

	t.Run("ShouldValidateTrustAnchorOfAttCAForFIDOU2F", func(t *testing.T) {
		attca := &metadata.Entry{
			MetadataStatement: metadata.Statement{
				AttestationTypes:            metadata.AuthenticatorAttestationTypes{metadata.AttCA},
				AttestationRootCertificates: []*x509.Certificate{root},
			},
		}

		mds := metadataTestExtendedProvider(t, map[uuid.UUID]*metadata.Entry{}, map[string]*metadata.Entry{hex.EncodeToString(withSKI.SubjectKeyId): attca},
			memory.WithValidateEntry(true),
			memory.WithValidateTrustAnchor(true),
			memory.WithValidateAttestationTypes(true),
			memory.WithValidateEntryKeyIdentifier(true),
		)

		assert.Nil(t, ValidateMetadata(context.Background(), mds, uuid.Nil, string(metadata.AttCA), "fido-u2f", []any{withSKI.Raw}))
	})
}

func TestValidateMetadataExtendedStatusCertificateScope(t *testing.T) {
	aaguid := uuid.MustParse("0865c31d-05dc-4fb1-adce-3227bfb19967")

	root, rootKey := metadataTestGenerateCertificate(t, "Metadata Root", nil, nil)
	compromised, _ := metadataTestGenerateCertificate(t, "Compromised Batch", root, rootKey)
	unaffected, _ := metadataTestGenerateCertificate(t, "Unaffected Batch", root, rootKey)

	effective := time.Now().Add(-time.Hour)

	testCases := []struct {
		name   string
		report metadata.StatusReport
		scope  bool
		x5cs   []any
		err    bool
	}{
		{
			name:   "ShouldIgnoreCompromiseOfOtherBatchCertificate",
			report: metadata.StatusReport{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective, BatchCertificate: compromised},
			scope:  true,
			x5cs:   []any{unaffected.Raw},
		},
		{
			name:   "ShouldIgnoreCompromiseOfOtherCertificate",
			report: metadata.StatusReport{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective, Certificate: compromised},
			scope:  true,
			x5cs:   []any{unaffected.Raw},
		},
		{
			name:   "ShouldApplyCompromiseOfBatchCertificate",
			report: metadata.StatusReport{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective, BatchCertificate: compromised},
			scope:  true,
			x5cs:   []any{compromised.Raw},
			err:    true,
		},
		{
			name:   "ShouldApplyCompromiseOfIntermediateCertificate",
			report: metadata.StatusReport{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective, Certificate: root},
			scope:  true,
			x5cs:   []any{unaffected.Raw, root.Raw},
			err:    true,
		},
		{
			name:   "ShouldApplyCompromiseOfOtherBatchWhenDisabled",
			report: metadata.StatusReport{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective, BatchCertificate: compromised},
			x5cs:   []any{unaffected.Raw},
			err:    true,
		},
		{
			name:   "ShouldApplyCompromiseOfOtherBatchWithoutTrustPath",
			report: metadata.StatusReport{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective, BatchCertificate: compromised},
			scope:  true,
			err:    true,
		},
		{
			name:   "ShouldApplyUnscopedCompromise",
			report: metadata.StatusReport{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective},
			scope:  true,
			x5cs:   []any{unaffected.Raw},
			err:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			entry := &metadata.Entry{
				AaGUID:        aaguid,
				StatusReports: []metadata.StatusReport{{Status: metadata.FidoCertified, EffectiveDate: &effective}, tc.report},
			}

			mds := metadataTestExtendedProvider(t, map[uuid.UUID]*metadata.Entry{aaguid: entry}, nil,
				memory.WithValidateStatus(true),
				memory.WithValidateStatusCertificateScope(tc.scope),
			)

			actual := ValidateMetadata(context.Background(), mds, aaguid, string(metadata.BasicFull), "packed", tc.x5cs)

			if !tc.err {
				assert.Nil(t, actual)

				return
			}

			require.NotNil(t, actual)
			assert.Contains(t, actual.DevInfo, "Error occurred validating the authenticator status")
		})
	}
}

func TestValidateMetadataExtendedStatusCertificateScopeEmpty(t *testing.T) {
	aaguid := uuid.MustParse("0865c31d-05dc-4fb1-adce-3227bfb19967")

	root, rootKey := metadataTestGenerateCertificate(t, "Metadata Root", nil, nil)
	compromised, _ := metadataTestGenerateCertificate(t, "Compromised Batch", root, rootKey)
	unaffected, _ := metadataTestGenerateCertificate(t, "Unaffected Batch", root, rootKey)

	effective := time.Now().Add(-time.Hour)

	entry := &metadata.Entry{
		AaGUID:        aaguid,
		StatusReports: []metadata.StatusReport{{Status: metadata.AttestationKeyCompromise, EffectiveDate: &effective, BatchCertificate: compromised}},
	}

	testCases := []struct {
		name string
		opts []memory.Option
		err  string
	}{
		{
			name: "ShouldFailWhenDesiredStatusesConfigured",
			opts: []memory.Option{memory.WithStatusDesired([]metadata.AuthenticatorStatus{metadata.FidoCertified})},
			err:  "Error occurred validating the authenticator status",
		},
		{
			name: "ShouldPassWhenOnlyUndesiredStatusesConfigured",
			opts: []memory.Option{memory.WithStatusUndesired(metadata.DefaultUndesiredAuthenticatorStatuses())},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			require.Empty(t, metadataStatusReportsInScope(entry.StatusReports, []*x509.Certificate{unaffected}))

			opts := append([]memory.Option{
				memory.WithValidateStatus(true),
				memory.WithValidateStatusCertificateScope(true),
			}, tc.opts...)

			mds := metadataTestExtendedProvider(t, map[uuid.UUID]*metadata.Entry{aaguid: entry}, nil, opts...)

			actual := ValidateMetadata(context.Background(), mds, aaguid, string(metadata.BasicFull), "packed", []any{unaffected.Raw})

			if tc.err == "" {
				assert.Nil(t, actual)

				return
			}

			require.NotNil(t, actual)
			assert.Contains(t, actual.DevInfo, tc.err)
		})
	}
}

func TestMetadataStatusReportsInScope(t *testing.T) {
	root, rootKey := metadataTestGenerateCertificate(t, "Metadata Root", nil, nil)
	cert, _ := metadataTestGenerateCertificate(t, "Attestation", root, rootKey)

	reports := []metadata.StatusReport{
		{Status: metadata.FidoCertified},
		{Status: metadata.AttestationKeyCompromise, Certificate: root},
	}

	assert.Equal(t, reports[:1], metadataStatusReportsInScope(reports, []*x509.Certificate{cert}))
	assert.Equal(t, reports, metadataStatusReportsInScope(reports, []*x509.Certificate{cert, root}))
}

// Supporting functions and test data.

func metadataTestExtendedProvider(t *testing.T, entries map[uuid.UUID]*metadata.Entry, keyIDs map[string]*metadata.Entry, opts ...memory.Option) metadata.Provider {
	t.Helper()

	opts = append([]memory.Option{
		memory.WithMetadata(entries),
		memory.WithMetadataKeyIdentifiers(keyIDs),
		memory.WithValidateEntry(false),
		memory.WithValidateTrustAnchor(false),
		memory.WithValidateStatus(false),
		memory.WithValidateAttestationTypes(false),
	}, opts...)

	mds, err := memory.New(opts...)
	require.NoError(t, err)

	_, ok := mds.(metadata.ExtendedProvider)
	require.True(t, ok)

	return mds
}

func metadataTestCredentialPublicKey(t *testing.T, alg webauthncose.COSEAlgorithmIdentifier) []byte {
	t.Helper()

	data, err := webauthncbor.Marshal(map[int]int{1: int(webauthncose.EllipticKey), 3: int(alg)})
	require.NoError(t, err)

	return data
}

func metadataTestExtensions(t *testing.T, extensions map[string]any) []byte {
	t.Helper()

	data, err := webauthncbor.Marshal(extensions)
	require.NoError(t, err)

	return data
}

// metadataTestGenerateLeafCertificate issues a leaf certificate, which unlike a certificate authority certificate is
// not automatically issued with the Subject Key Identifier extension.
func metadataTestGenerateLeafCertificate(t *testing.T, parent *x509.Certificate, parentKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "Attestation Leaf"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, &key.PublicKey, parentKey)
	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)
	require.NoError(t, err)

	return cert
}

func metadataTestPublicKeyHash(t *testing.T, cert *x509.Certificate) string {
	t.Helper()

	key, ok := cert.PublicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	raw, err := key.Bytes()
	require.NoError(t, err)

	sum := sha1.Sum(raw) //nolint:gosec // SHA-1 is mandated for the RFC5280 method 1 key identifier.

	return hex.EncodeToString(sum[:])
}
