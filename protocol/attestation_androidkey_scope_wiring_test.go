package protocol_test

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
	"github.com/go-webauthn/webauthn/webauthn"
)

func TestCreateCredential_AndroidKeyAuthorizationScope(t *testing.T) {
	const (
		errTEEEnforced = "Attestation certificate extensions contains teeEnforced authorization list with origin not equal KM_ORIGIN_GENERATED"
		errUnion       = "Attestation certificate extensions contains authorization list with origin not equal KM_ORIGIN_GENERATED"
	)

	testCases := []struct {
		name        string
		attestation protocol.AttestationPolicy
		err         string
	}{
		{
			name:        "ShouldRejectSoftwareBackedKeyUnderDefaultScope",
			attestation: protocol.AttestationPolicy{},
			err:         errTEEEnforced,
		},
		{
			name: "ShouldRejectSoftwareBackedKeyUnderTEEEnforcedScope",
			attestation: protocol.AttestationPolicy{
				AndroidKey: protocol.AndroidKeyPolicy{AuthorizationScope: protocol.AndroidKeyAuthorizationScopeTEEEnforced},
			},
			err: errTEEEnforced,
		},
		{
			name: "ShouldRejectSoftwareBackedKeyUnderUnionScopeWithUnionWording",
			attestation: protocol.AttestationPolicy{
				AndroidKey: protocol.AndroidKeyPolicy{AuthorizationScope: protocol.AndroidKeyAuthorizationScopeUnion},
			},
			err: errUnion,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, challenge := androidKeyScopeWiringSpecVector(t)

			parsedResponse, err := protocol.ParseCredentialCreationResponseBytes(body)
			require.NoError(t, err)

			userID := []byte("test-user-id")

			w := &webauthn.WebAuthn{
				Config: &webauthn.Config{
					RPID:        "example.org",
					RPOrigins:   []string{"https://example.org"},
					Attestation: tc.attestation,
				},
			}

			session := webauthn.SessionData{
				Challenge:  challenge,
				UserID:     userID,
				CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256}},
			}

			credential, err := w.CreateCredential(androidKeyScopeWiringTestUser{id: userID}, session, parsedResponse)

			assert.Nil(t, credential)
			assert.EqualError(t, err, tc.err)
		})
	}
}

type androidKeyScopeWiringTestUser struct {
	id []byte
}

func (u androidKeyScopeWiringTestUser) WebAuthnID() []byte                         { return u.id }
func (u androidKeyScopeWiringTestUser) WebAuthnName() string                       { return "test-user" }
func (u androidKeyScopeWiringTestUser) WebAuthnDisplayName() string                { return "Test User" }
func (u androidKeyScopeWiringTestUser) WebAuthnCredentials() []webauthn.Credential { return nil }

func androidKeyScopeWiringSpecVector(t *testing.T) (body []byte, challenge string) {
	t.Helper()

	const (
		attestationObjectHex = "a363666d746b616e64726f69642d6b65796761747453746d74a363616c67266373696758483046022100e95512982aa3f216cff2e87c8ec57057b8529f674eaabeccaa27fd03d8779f19022100afb6bf459da4a826f00d01fc6b60712ff31dc4eb331619c8f874bb17e4314e94637835638159026e3082026a30820210a00302010202101ff91f76b63f44812f998b250b0286bf300a06082a8648ce3d0403023062311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331253023060355040b0c1c41757468656e74696361746f72204174746573746174696f6e204341310b30090603550406130241413020170d3234303130313030303030305a180f33303234303130313030303030305a305f311e301c06035504030c15576562417574686e207465737420766563746f7273310c300a060355040a0c0357334331223020060355040b0c1941757468656e74696361746f72204174746573746174696f6e310b30090603550406130241413059301306072a8648ce3d020106082a8648ce3d0301070342000499169657036d089a2a9821a7d0063d341f1a4613389359636efab5f3cbf1accfdd91c55543176ea99b644406dd1dd63774b6af65ac759e06ff40b1c8ab02df6ba381a83081a5300c0603551d130101ff04023000300e0603551d0f0101ff040403020780301d0603551d0e041604141ac81e50641e8d1339ab9f7eb25f0cd5aac054b0301f0603551d2304183016801445aff715b0dd786741fee996ebc16547a3931b1e3045060a2b06010401d679020111043730350202012c0a01000201000a01000420b435028d7b6a8f83bb461d41c19b053a9d3cdb30351a4f374cd4cde8dbefb606040030003000300a06082a8648ce3d040302034800304502202d27f0ca39d2f519fc8f49c6d96dfc793059e211ff80516a50398cf1eac2a322022100d482a88c740f64cf6a98ccc6c8b9f5e1e533fa5e509f0a7b4c3a02f964a8eba768617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000ade9705e1ce7085b899a540d02199bf800200a4729519788b6ed8a2d772b494e186244d8c798c052960dbc8c10c915176795a501020326200121582099169657036d089a2a9821a7d0063d341f1a4613389359636efab5f3cbf1accf225820dd91c55543176ea99b644406dd1dd63774b6af65ac759e06ff40b1c8ab02df6b"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2250654877747a5a647a4e345f384d76795869625f7037725f682d385162494438686c334541746d57414641222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205656316351755232714c4d5f616d50666f487a4c3067227d"
		credentialIDHex      = "0a4729519788b6ed8a2d772b494e186244d8c798c052960dbc8c10c915176795" //nolint:gosec
		challengeHex         = "3de1f0b7365dccde3ff0cbf25e26ffa7baff87ef106c80fc865dc402d9960050"
	)

	credentialID, err := hex.DecodeString(credentialIDHex)
	require.NoError(t, err)

	challengeBytes, err := hex.DecodeString(challengeHex)
	require.NoError(t, err)

	challenge = base64.RawURLEncoding.EncodeToString(challengeBytes)

	attestationObjectBytes, err := hex.DecodeString(attestationObjectHex)
	require.NoError(t, err)

	clientDataJSONBytes, err := hex.DecodeString(clientDataJSONHex)
	require.NoError(t, err)

	id := base64.RawURLEncoding.EncodeToString(credentialID)
	attObj := base64.RawURLEncoding.EncodeToString(attestationObjectBytes)
	cdj := base64.RawURLEncoding.EncodeToString(clientDataJSONBytes)

	response := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": attObj,
			"clientDataJSON":    cdj,
		},
	}

	body, err = json.Marshal(response)
	require.NoError(t, err)

	return body, challenge
}
