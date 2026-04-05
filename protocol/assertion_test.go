package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestParseCredentialRequestResponse(t *testing.T) {
	byteID, _ := base64.RawURLEncoding.DecodeString("AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng")
	byteAAGUID, _ := base64.RawURLEncoding.DecodeString("rc4AAjW8xgpkiwsl8fBVAw")
	byteRPIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ")
	byteSignature, _ := base64.RawURLEncoding.DecodeString("MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc")
	byteUserHandle, _ := base64.RawURLEncoding.DecodeString("0ToAAAAAAAAAAA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9")

	type args struct {
		responseName string
	}

	testCases := []struct {
		name       string
		args       args
		expected   *ParsedCredentialAssertionData
		err        string
		errType    string
		errDetails string
		errInfo    string
	}{
		{
			name: "ShouldParseCredentialAssertion",
			args: args{
				"success",
			},
			expected: &ParsedCredentialAssertionData{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
						Type: string(PublicKeyCredentialType),
					},
					RawID: byteID,
					ClientExtensionResults: map[string]any{
						"appID": "example.com",
					},
				},
				Response: ParsedAssertionResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.get"),
						Challenge: "E4PTcIH_HfX1pC6Sigk1SC9NAlgeztN0439vi8z_c9k",
						Origin:    "https://webauthn.io",
						Hint:      "do not compare clientDataJSON against a template. See https://goo.gl/yabPex",
					},
					AuthenticatorData: AuthenticatorData{
						RPIDHash: byteRPIDHash,
						Counter:  1553097241,
						Flags:    0x045,
						AttData: AttestedCredentialData{
							AAGUID:              byteAAGUID,
							CredentialID:        byteID,
							CredentialPublicKey: byteCredentialPubKey,
						},
					},
					Signature:  byteSignature,
					UserHandle: byteUserHandle,
				},
				Raw: CredentialAssertionResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							Type: string(PublicKeyCredentialType),
							ID:   "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
						},
						RawID: byteID,
						ClientExtensionResults: map[string]any{
							"appID": "example.com",
						},
					},
					AssertionResponse: AuthenticatorAssertionResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AuthenticatorData: byteAuthData,
						Signature:         byteSignature,
						UserHandle:        byteUserHandle,
					},
				},
			},
			err: "",
		},
		{
			name: "ShouldHandleTrailingData",
			args: args{
				"trailingData",
			},
			expected:   nil,
			err:        "Parse error for Assertion",
			errType:    "invalid_request",
			errDetails: "Parse error for Assertion",
			errInfo:    "body contains trailing data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			body := io.NopCloser(bytes.NewReader([]byte(testAssertionResponses[tc.args.responseName])))

			actual, err := ParseCredentialRequestResponseBody(body)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)

				AssertIsProtocolError(t, err, tc.errType, tc.errDetails, tc.errInfo)

				return
			}

			require.NoError(t, err)

			assert.Equal(t, tc.expected.ClientExtensionResults, actual.ClientExtensionResults)
			assert.Equal(t, tc.expected.ID, actual.ID)
			assert.Equal(t, tc.expected.ParsedCredential, actual.ParsedCredential)
			assert.Equal(t, tc.expected.ParsedPublicKeyCredential, actual.ParsedPublicKeyCredential)
			assert.Equal(t, tc.expected.Raw, actual.Raw)
			assert.Equal(t, tc.expected.RawID, actual.RawID)

			assert.Equal(t, tc.expected.Response.CollectedClientData, actual.Response.CollectedClientData)

			var (
				pkExpected, pkActual any
			)

			assert.NoError(t, webauthncbor.Unmarshal(tc.expected.Response.AuthenticatorData.AttData.CredentialPublicKey, &pkExpected))
			assert.NoError(t, webauthncbor.Unmarshal(actual.Response.AuthenticatorData.AttData.CredentialPublicKey, &pkActual))

			assert.Equal(t, pkExpected, pkActual)
			assert.NotEqual(t, nil, pkExpected)
			assert.NotEqual(t, nil, pkActual)
		})
	}
}

func TestParseCredentialRequestResponse_NilRequest(t *testing.T) {
	testCases := []struct {
		name    string
		request *http.Request
		err     string
	}{
		{
			name:    "ShouldFailNilRequest",
			request: nil,
			err:     "No response given",
		},
		{
			name:    "ShouldFailNilBody",
			request: &http.Request{},
			err:     "No response given",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCredentialRequestResponse(tc.request)
			assert.Nil(t, result)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestParseCredentialRequestResponseBytes(t *testing.T) {
	testCases := []struct {
		name       string
		data       []byte
		err        string
		errType    string
		errDetails string
		errInfo    string
	}{
		{
			name:       "ShouldFailInvalidJSON",
			data:       []byte("not json"),
			err:        "Parse error for Assertion",
			errType:    "invalid_request",
			errDetails: "Parse error for Assertion",
			errInfo:    "invalid character 'o' in literal null (expecting 'u')",
		},
		{
			name:       "ShouldFailTrailingData",
			data:       []byte(testAssertionResponses["trailingData"]),
			err:        "Parse error for Assertion",
			errType:    "invalid_request",
			errDetails: "Parse error for Assertion",
			errInfo:    "body contains trailing data",
		},
		{
			name: "ShouldSucceed",
			data: []byte(testAssertionResponses["success"]),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := ParseCredentialRequestResponseBytes(tc.data)
			if tc.err != "" {
				assert.Nil(t, result)
				assert.EqualError(t, err, tc.err)
				AssertIsProtocolError(t, err, tc.errType, tc.errDetails, tc.errInfo)
			} else {
				require.NoError(t, err)
				require.NotNil(t, result)
			}
		})
	}
}

func TestCredentialAssertionResponse_Parse_Errors(t *testing.T) {
	testCases := []struct {
		name string
		car  CredentialAssertionResponse
		err  string
	}{
		{
			name: "ShouldFailMissingID",
			car:  CredentialAssertionResponse{},
			err:  "CredentialAssertionResponse with ID missing",
		},
		{
			name: "ShouldFailIDNotBase64",
			car: CredentialAssertionResponse{
				PublicKeyCredential: PublicKeyCredential{
					Credential: Credential{
						ID: "not valid base64 %%%",
					},
				},
			},
			err: "CredentialAssertionResponse with ID not base64url encoded",
		},
		{
			name: "ShouldFailBadType",
			car: CredentialAssertionResponse{
				PublicKeyCredential: PublicKeyCredential{
					Credential: Credential{
						ID:   "dGVzdA",
						Type: "bad-type",
					},
				},
			},
			err: "CredentialAssertionResponse with bad type",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.car.Parse()
			assert.Nil(t, result)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestParsedCredentialAssertionData_Verify(t *testing.T) {
	par, credPubKey, challenge := testAssertionSpecVectorNoneES256(t)

	// Valid but wrong public key (from the packed self ES256 spec test vector).
	wrongKey, err := hex.DecodeString("a5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2")
	require.NoError(t, err)

	testCases := []struct {
		name            string
		challenge       string
		relyingPartyID  string
		rpOrigins       []string
		appID           string
		credentialBytes []byte
		err             string
	}{
		{
			name:            "ShouldSucceed",
			challenge:       challenge,
			relyingPartyID:  "example.org",
			rpOrigins:       []string{"https://example.org"},
			credentialBytes: credPubKey,
		},
		{
			name:            "ShouldFailClientDataVerification",
			challenge:       "wrong-challenge",
			relyingPartyID:  "example.org",
			rpOrigins:       []string{"https://example.org"},
			credentialBytes: credPubKey,
			err:             "Error validating challenge",
		},
		{
			name:            "ShouldFailAuthDataVerification",
			challenge:       challenge,
			relyingPartyID:  "wrong-rp-id.example.com",
			rpOrigins:       []string{"https://example.org"},
			credentialBytes: credPubKey,
			err:             "Error validating the authenticator response",
		},
		{
			name:            "ShouldFailInvalidPublicKey",
			challenge:       challenge,
			relyingPartyID:  "example.org",
			rpOrigins:       []string{"https://example.org"},
			credentialBytes: []byte("invalid-key"),
			err:             "Error parsing the assertion public key: Unsupported Public Key Type",
		},
		{
			name:            "ShouldFailSignatureVerification",
			challenge:       challenge,
			relyingPartyID:  "example.org",
			rpOrigins:       []string{"https://example.org"},
			credentialBytes: wrongKey,
			err:             "Error validating the assertion signature: <nil>",
		},
		{
			name:            "ShouldFailWithAppID",
			challenge:       challenge,
			relyingPartyID:  "example.org",
			rpOrigins:       []string{"https://example.org"},
			appID:           "https://example.org",
			credentialBytes: credPubKey,
			err:             "Error parsing the assertion public key: failed to parse FIDO public key: crypto/ecdh: invalid public key",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := par.Verify(tc.challenge, tc.relyingPartyID, tc.rpOrigins, nil, TopOriginIgnoreVerificationMode, tc.appID, false, true, tc.credentialBytes)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestParseCredentialRequestResponse_Success(t *testing.T) {
	body := io.NopCloser(bytes.NewReader([]byte(testAssertionResponses["success"])))

	req := &http.Request{Body: body}

	result, err := ParseCredentialRequestResponse(req)
	require.NoError(t, err)
	require.NotNil(t, result)
	assert.Equal(t, "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng", result.ID)
}

func TestCredentialAssertionResponse_Parse_AuthenticatorAttachment(t *testing.T) {
	testCases := []struct {
		name               string
		attachment         string
		expectedAttachment AuthenticatorAttachment
	}{
		{
			name:               "ShouldHandlePlatform",
			attachment:         "platform",
			expectedAttachment: Platform,
		},
		{
			name:               "ShouldHandleCrossPlatform",
			attachment:         "cross-platform",
			expectedAttachment: CrossPlatform,
		},
		{
			name:               "ShouldHandleEmpty",
			attachment:         "",
			expectedAttachment: "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			response := testAssertionResponses["success"]

			var raw map[string]any

			require.NoError(t, json.Unmarshal([]byte(response), &raw))

			if tc.attachment != "" {
				raw["authenticatorAttachment"] = tc.attachment
			}

			data, err := json.Marshal(raw)
			require.NoError(t, err)

			result, err := ParseCredentialRequestResponseBytes(data)
			require.NoError(t, err)
			assert.Equal(t, tc.expectedAttachment, result.AuthenticatorAttachment)
		})
	}
}

func TestCredentialAssertionResponse_Parse_ClientDataJSONError(t *testing.T) {
	car := CredentialAssertionResponse{
		PublicKeyCredential: PublicKeyCredential{
			Credential: Credential{
				ID:   "dGVzdA",
				Type: string(PublicKeyCredentialType),
			},
		},
		AssertionResponse: AuthenticatorAssertionResponse{
			AuthenticatorResponse: AuthenticatorResponse{
				ClientDataJSON: []byte("not valid json"),
			},
			AuthenticatorData: []byte{
				// Minimal valid auth data: 32 bytes rpIdHash + 1 byte flags + 4 bytes counter = 37 bytes.
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
				0x01,       // flags: UP
				0, 0, 0, 0, // counter
			},
		},
	}

	result, err := car.Parse()
	assert.Nil(t, result)
	require.Error(t, err)
}

func TestCredentialAssertionResponse_Parse_AuthDataError(t *testing.T) {
	car := CredentialAssertionResponse{
		PublicKeyCredential: PublicKeyCredential{
			Credential: Credential{
				ID:   "dGVzdA",
				Type: string(PublicKeyCredentialType),
			},
		},
		AssertionResponse: AuthenticatorAssertionResponse{
			AuthenticatorResponse: AuthenticatorResponse{
				ClientDataJSON: []byte(`{"type":"webauthn.get","challenge":"dGVzdA","origin":"https://example.org"}`),
			},
			AuthenticatorData: []byte{0x01, 0x02}, // Too short to be valid.
		},
	}

	result, err := car.Parse()
	assert.Nil(t, result)
	assert.EqualError(t, err, "Error unmarshalling auth data")
}

// testAssertionSpecVectorNoneES256 returns a parsed assertion and credentials for testing.
func testAssertionSpecVectorNoneES256(t *testing.T) (par *ParsedCredentialAssertionData, credPubKey []byte, challenge string) {
	t.Helper()

	const (
		authenticatorDataHex = "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d"
		signatureHex         = "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87"
		credentialIDHex      = "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4" //nolint:gosec
		challengeHex         = "39c0e7521417ba54d43e8dc95174f423dee9bf3cd804ff6d65c857c9abf4d408"
		credentialPubKeyHex  = "a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220"
	)

	credentialID, err := hex.DecodeString(credentialIDHex)
	require.NoError(t, err)

	credPubKey, err = hex.DecodeString(credentialPubKeyHex)
	require.NoError(t, err)

	challenge = base64.RawURLEncoding.EncodeToString(assertionTestDecodeHex(t, challengeHex))

	id := base64.RawURLEncoding.EncodeToString(credentialID)
	authenticatorData := base64.RawURLEncoding.EncodeToString(assertionTestDecodeHex(t, authenticatorDataHex))
	clientDataJSON := base64.RawURLEncoding.EncodeToString(assertionTestDecodeHex(t, clientDataJSONHex))
	signature := base64.RawURLEncoding.EncodeToString(assertionTestDecodeHex(t, signatureHex))

	body := map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": authenticatorData,
			"clientDataJSON":    clientDataJSON,
			"signature":         signature,
		},
	}

	data, err := json.Marshal(body)
	require.NoError(t, err)

	par, err = ParseCredentialRequestResponseBytes(data)
	require.NoError(t, err)

	return par, credPubKey, challenge
}

func assertionTestDecodeHex(t *testing.T, s string) []byte {
	t.Helper()

	data, err := hex.DecodeString(s)
	require.NoError(t, err)

	return data
}

var testAssertionResponses = map[string]string{
	// None Attestation - MacOS TouchID.
	`success`: `{
		"id":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"rawId":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"clientExtensionResults":{"appID":"example.com"},
		"type":"public-key",
		"response":{
			"authenticatorData":"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
			"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
			"signature":"MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc",
			"userHandle":"0ToAAAAAAAAAAA"}
		}
	`,
	`trailingData`: `{
		"id":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"rawId":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"clientExtensionResults":{"appID":"example.com"},
		"type":"public-key",
		"response":{
			"authenticatorData":"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
			"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
			"signature":"MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc",
			"userHandle":"0ToAAAAAAAAAAA"}
		}

trailing
	`,
}
