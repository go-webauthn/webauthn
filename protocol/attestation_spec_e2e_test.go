package protocol

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"testing"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/testing/mocks"
)

// WebAuthn Level 3 §16 End-to-End Test Vectors
//
// These tests exercise the full cradle-to-grave path:
//   - Registration: ParseCredentialCreationResponseBody → ParsedCredentialCreationData.Verify
//   - Authentication: ParseCredentialRequestResponseBody → ParsedCredentialAssertionData.Verify
//
// The spec test vectors that support full attestation (packed with x5c) are validated with a
// custom metadata.Provider that trusts the spec's synthetic attestation CA certificate.
//
// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors

func TestSpecVectors_Registration_E2E(t *testing.T) {
	testCases := []struct {
		name              string
		attestationObject string
		clientDataJSON    string
		credentialID      string
		challenge         string
		format            string
		credParams        []CredentialParameter
		mds               metadata.Provider
	}{
		//nolint:gosec
		{
			// §16.2 None Attestation - ES256
			// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256
			name:              "NoneES256",
			attestationObject: "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d",
			credentialID:      "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4",
			challenge:         "00c30fb78531c464d2b6771dab8d7b603c01162f2fa486bea70f283ae556e130",
			format:            "none",
			credParams:        []CredentialParameter{{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
		},
		//nolint:gosec
		{
			// §16.3 Self Attestation (Packed) - ES256
			// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-packed-self-es256
			name:              "PackedSelfES256",
			attestationObject: "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d",
			credentialID:      "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c",
			challenge:         "7869c2b772d4b58eba9378cf8f29e26cf935aa77df0da89fa99c0bdc0a76f7e5",
			format:            "packed",
			credParams:        []CredentialParameter{{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
		},
		//nolint:gosec
		{
			// §16.7 Packed Attestation - ES256 (Full Attestation with x5c and MDS)
			// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-packed-es256
			name:              "PackedES256WithMDS",
			attestationObject: "a363666d74667061636b65646761747453746d74a363616c6726637369675847304502203f19ec4b229f46ab8c45eff29b904ff10c0390dc40bf1216f04a78f4ceba3425022100fe7041a32759aff05a0f9f26c70a999c7a284451ba89234a1d3483c25e21925b637835638159022530820221308201c8a00302010202110088c220f83c8ef1feafe94deae45faad0300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d03010703420004a91ba4389409dd38a428141940ca8feb1ac0d7b4350558104a3777a49322f3798440f378b3398ab2d3bb7bf91322c92eb23556f59ad0a836fec4c7663b0e4dc3a360305e300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e04160414a589ba72d060842ab11f74fb246bdedab16f9b9b301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d040302034700304402201726b9d85ecd8a5ed51163722ca3a20886fd9b242a0aa0453d442116075defd502207ef471e530ac87961a88a7f0d0c17b091ffc6b9238d30f79f635b417be5910e768617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b54d00000000876ca4f52071c3e9b25509ef2cdf7ed60020c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a227752684b58393334424634543345663153324831706c61325a725751475046746877365356756d56494249222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20396138624e596a4b436757724258552d66436c316167227d",
			credentialID:      "c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5",
			challenge:         "c1184a5fddf8045e13dc47f54b61f5a656b666b59018f16d870e9256e9952012",
			format:            "packed",
			credParams:        []CredentialParameter{{Type: PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
			mds:               specTestMDSProvider(t),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := specTestBuildRegistrationJSON(t, tc.credentialID, tc.attestationObject, tc.clientDataJSON)

			pcc, err := ParseCredentialCreationResponseBody(bytes.NewReader(body))
			require.NoError(t, err)

			challenge := base64.RawURLEncoding.EncodeToString(specTestDecodeHex(t, tc.challenge))

			_, err = pcc.Verify(challenge, false, true, specTestRPID, []string{specTestOrigin}, nil, TopOriginIgnoreVerificationMode, tc.mds, tc.credParams)
			require.NoError(t, err)

			assert.Equal(t, tc.format, pcc.Response.AttestationObject.Format)
			assert.Equal(t, specTestDecodeHex(t, tc.credentialID), pcc.Response.AttestationObject.AuthData.AttData.CredentialID)
		})
	}
}

func TestSpecVectors_Authentication_E2E(t *testing.T) {
	testCases := []struct {
		name              string
		authenticatorData string
		clientDataJSON    string
		signature         string
		userHandle        string
		credentialID      string
		challenge         string
		credentialPubKey  string
	}{
		//nolint:gosec
		{
			// §16.2 None Attestation - ES256 (Authentication)
			// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-none-es256
			name:              "NoneES256",
			authenticatorData: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
			signature:         "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87",
			credentialID:      "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4",
			challenge:         "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408",
			credentialPubKey:  "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
		},
		//nolint:gosec
		{
			// §16.3 Self Attestation (Packed) - ES256 (Authentication)
			// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-packed-self-es256
			name:              "PackedSelfES256",
			authenticatorData: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50900000000",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a225248696843784e534e493352594d45314f7731476d3132786e726b634a5f6666707637546e2d4a71386773222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a206754623533727a36456853576f6d58477a696d433151227d",
			signature:         "304402203310b9431903c401f1be2bdc8d23a4007682dbbddcf846994947b7f465daf84002204e94dd00047b316061b3b99772b7efd95994a83ef584b3b6b825ea3550251b66",
			credentialID:      "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c",
			challenge:         "4478a10b1352348dd160c1353b0d469b5db19eb91c27f7dfa6fed39fe26af20b",
			credentialPubKey:  "a5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
		},
		//nolint:gosec
		{
			// §16.7 Packed Attestation - ES256 (Authentication)
			// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-packed-es256
			name:              "PackedES256",
			authenticatorData: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50d00000000",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a2273524276704770587676463446524841565833496d4b4130453958773858306b526a44426c4d6668726255222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20415a4d77794d78496244382d756775464e7036723851227d",
			signature:         "30450220694969d3ee928de6f02ef23a9c644d7d779916451734a94b432542f498a1ebe90221008b0819c824218a97152cd099c55bfb1477b29d900a49a64018314f9bfccda163",
			credentialID:      "c9a6f5b3462d02873fea0c56862234f99f081728084e511bb7760201a89054a5",
			challenge:         "b1106fa46a57bef1781511c0557dc898a03413d5f0f17d244630c194c7e1adb5",
			credentialPubKey:  "a50102032620012158201cf27f25da591208a4239c2e324f104f585525479a29edeedd830f48e77aeae522582059e4b7da6c0106e206ce390c93ab98a15a5ec3887e57f0cc2bece803b920c423",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body := specTestBuildAssertionJSON(t, tc.credentialID, tc.authenticatorData, tc.clientDataJSON, tc.signature, tc.userHandle)

			par, err := ParseCredentialRequestResponseBody(bytes.NewReader(body))
			require.NoError(t, err)

			challenge := base64.RawURLEncoding.EncodeToString(specTestDecodeHex(t, tc.challenge))
			credPubKey := specTestDecodeHex(t, tc.credentialPubKey)

			assert.NoError(t, par.Verify(challenge, specTestRPID, []string{specTestOrigin}, nil, TopOriginIgnoreVerificationMode, "", false, true, credPubKey))
		})
	}
}

// Supporting constants, types, and functions.

const specTestOrigin = "https://example.org"

func specTestHexToBase64URL(t *testing.T, hexStr string) string {
	t.Helper()

	return base64.RawURLEncoding.EncodeToString(specTestDecodeHex(t, hexStr))
}

func specTestBuildRegistrationJSON(t *testing.T, credentialIDHex, attestationObjectHex, clientDataJSONHex string) []byte {
	t.Helper()

	id := specTestHexToBase64URL(t, credentialIDHex)
	attObj := specTestHexToBase64URL(t, attestationObjectHex)
	cdj := specTestHexToBase64URL(t, clientDataJSONHex)

	response := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": attObj,
			"clientDataJSON":    cdj,
		},
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	return data
}

func specTestBuildAssertionJSON(t *testing.T, credentialIDHex, authenticatorDataHex, clientDataJSONHex, signatureHex, userHandleHex string) []byte {
	t.Helper()

	id := specTestHexToBase64URL(t, credentialIDHex)

	resp := map[string]any{
		"authenticatorData": specTestHexToBase64URL(t, authenticatorDataHex),
		"clientDataJSON":    specTestHexToBase64URL(t, clientDataJSONHex),
		"signature":         specTestHexToBase64URL(t, signatureHex),
	}

	if userHandleHex != "" {
		resp["userHandle"] = specTestHexToBase64URL(t, userHandleHex)
	}

	response := map[string]any{
		"id":       id,
		"rawId":    id,
		"type":     "public-key",
		"response": resp,
	}

	data, err := json.Marshal(response)
	require.NoError(t, err)

	return data
}

// specTestMDSProvider returns a metadata.Provider that trusts the spec's synthetic attestation
// CA certificate (§16.1) for the packed ES256 AAGUID.
func specTestMDSProvider(t *testing.T) metadata.Provider {
	t.Helper()

	caCertDER := specTestDecodeHex(t, specTestCACertHex)

	caCert, err := x509.ParseCertificate(caCertDER)
	require.NoError(t, err)

	packedAAGUID := uuid.Must(uuid.FromBytes(specTestDecodeHex(t, "876ca4f52071c3e9b25509ef2cdf7ed6")))

	entry := &metadata.Entry{
		MetadataStatement: metadata.Statement{
			AttestationTypes:            metadata.AuthenticatorAttestationTypes{metadata.BasicFull},
			AttestationRootCertificates: []*x509.Certificate{caCert},
		},
		StatusReports: []metadata.StatusReport{
			{Status: metadata.FidoCertified},
		},
	}

	ctrl := gomock.NewController(t)
	mds := mocks.NewMockMetadataProvider(ctrl)

	mds.EXPECT().GetEntry(gomock.Any(), gomock.Any()).DoAndReturn(func(_ interface{}, aaguid uuid.UUID) (*metadata.Entry, error) {
		if aaguid == packedAAGUID {
			return entry, nil
		}

		return nil, nil
	}).AnyTimes()
	mds.EXPECT().GetValidateEntry(gomock.Any()).Return(false).AnyTimes()
	mds.EXPECT().GetValidateEntryPermitZeroAAGUID(gomock.Any()).Return(true).AnyTimes()
	mds.EXPECT().GetValidateTrustAnchor(gomock.Any()).Return(true).AnyTimes()
	mds.EXPECT().GetValidateStatus(gomock.Any()).Return(false).AnyTimes()
	mds.EXPECT().GetValidateAttestationTypes(gomock.Any()).Return(true).AnyTimes()

	return mds
}

// §16.1 Attestation Root Certificate used in tests.
const specTestCACertHex = "30820207308201ada003020102021100ed7f905d8bd0b414d1784913170a90b6300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a3062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d030107034200043269300e5ff7b699015f70cf80a8763bf705bc2e2af0c1b39cff718b7c35880ca30f319078d91b03389a006fdfc8a1dcd84edfa07d30aa13474a248a0dab5baaa3423040300f0603551d130101ff040530030101ff300e0603551d0f0101ff040403020106301d0603551d0e0416041445aff715b0dd786741fee996ebc16547a3931b1e300a06082a8648ce3d04030203480030450220483063b6bb08dcc83da33a02c11d2f42203176893554d138c614a36908724cc8022100f5ef2c912d4500b3e2f5b591d0622491e9f220dfd1f9734ec484bb7e90887663"

func TestSpecVectors_CACertificate(t *testing.T) {
	raw := specTestDecodeHex(t, specTestCACertHex)
	cert, err := x509.ParseCertificate(raw)
	require.NoError(t, err)

	assert.Equal(t, "WebAuthn test vectors", cert.Subject.CommonName)
	assert.Equal(t, "W3C", cert.Subject.Organization[0])
	assert.Equal(t, "Authenticator Attestation CA", cert.Subject.OrganizationalUnit[0])
	assert.True(t, cert.IsCA)
}
