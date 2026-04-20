package protocol

import (
	"bytes"
	"encoding/base64"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestParseCredentialCreationResponse(t *testing.T) {
	type args struct {
		responseName string
	}

	byteID, _ := base64.RawURLEncoding.DecodeString("6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteRPIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pSJYIMfCKfxl2SvnqJIiHQysHmpmITNgtCkQ5ESExSRjqrhXAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNc")
	byteAttObject, _ := base64.RawURLEncoding.DecodeString("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ")

	testCases := []struct {
		name       string
		args       args
		expected   *ParsedCredentialCreationData
		err        string
		errType    string
		errDetails string
		errInfo    string
	}{
		{
			name: "ShouldParseCredentialRequest",
			args: args{
				responseName: "success",
			},
			expected: &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: string(PublicKeyCredentialType),
					},
					RawID: byteID,
					ClientExtensionResults: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
					AuthenticatorAttachment: Platform,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "none",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRPIDHash,
							Counter:  0,
							Flags:    0x041,
							AttData: AttestedCredentialData{
								AAGUID:              make([]byte, 16),
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
					},
					Transports: []AuthenticatorTransport{USB, NFC, "fake"},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							Type: string(PublicKeyCredentialType),
							ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						},
						RawID: byteID,
						ClientExtensionResults: AuthenticationExtensionsClientOutputs{
							"appid": true,
						},
						AuthenticatorAttachment: "platform",
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
						Transports:        []string{"usb", "nfc", "fake"},
					},
				},
			},
			err: "",
		},
		{
			name: "ShouldHandleTrailingData",
			args: args{
				responseName: "trailingData",
			},
			expected:   nil,
			err:        "Parse error for Registration",
			errType:    "invalid_request",
			errDetails: "Parse error for Registration",
			errInfo:    "body contains trailing data",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			for _, subtest := range []string{"Response", "ResponseBody", "Bytes"} {
				t.Run(subtest, func(t *testing.T) {
					var (
						actual *ParsedCredentialCreationData
						err    error
					)

					switch subtest {
					case "Response":
						body := io.NopCloser(bytes.NewReader([]byte(testCredentialRequestResponses[tc.args.responseName])))

						request := &http.Request{
							Body: body,
						}

						actual, err = ParseCredentialCreationResponse(request)
					case "ResponseBody":
						body := io.NopCloser(bytes.NewReader([]byte(testCredentialRequestResponses[tc.args.responseName])))

						actual, err = ParseCredentialCreationResponseBody(body)
					case "Bytes":
						body := []byte(testCredentialRequestResponses[tc.args.responseName])

						actual, err = ParseCredentialCreationResponseBytes(body)
					}

					if tc.err != "" {
						assert.EqualError(t, err, tc.err)

						AssertIsProtocolError(t, err, tc.errType, tc.errDetails, tc.errInfo)

						return
					}

					assert.Equal(t, tc.expected.ClientExtensionResults, actual.ClientExtensionResults)
					assert.Equal(t, tc.expected.ID, actual.ID)
					assert.Equal(t, tc.expected.Type, actual.Type)
					assert.Equal(t, tc.expected.ParsedCredential, actual.ParsedCredential)
					assert.Equal(t, tc.expected.ParsedPublicKeyCredential, actual.ParsedPublicKeyCredential)
					assert.Equal(t, tc.expected.Raw, actual.Raw)
					assert.Equal(t, tc.expected.RawID, actual.RawID)
					assert.Equal(t, tc.expected.Response.Transports, actual.Response.Transports)
					assert.Equal(t, tc.expected.Response.CollectedClientData, actual.Response.CollectedClientData)
					assert.Equal(t, tc.expected.Response.AttestationObject.AuthData.AttData.CredentialID, actual.Response.AttestationObject.AuthData.AttData.CredentialID)
					assert.Equal(t, tc.expected.Response.AttestationObject.Format, actual.Response.AttestationObject.Format)

					var pkExpected, pkActual any

					pkBytesExpected := tc.expected.Response.AttestationObject.AuthData.AttData.CredentialPublicKey
					assert.NoError(t, webauthncbor.Unmarshal(pkBytesExpected, &pkExpected))

					pkBytesActual := actual.Response.AttestationObject.AuthData.AttData.CredentialPublicKey
					assert.NoError(t, webauthncbor.Unmarshal(pkBytesActual, &pkActual))

					assert.Equal(t, pkExpected, pkActual)
				})
			}
		})
	}
}

func TestParsedCredentialCreationData_Verify(t *testing.T) {
	byteID, _ := base64.RawURLEncoding.DecodeString("6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g")
	byteChallenge, _ := base64.RawURLEncoding.DecodeString("W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteRPIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pSJYIMfCKfxl2SvnqJIiHQysHmpmITNgtCkQ5ESExSRjqrhXAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNc")
	byteAttObject, _ := base64.RawURLEncoding.DecodeString("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ")

	type fields struct {
		ParsedPublicKeyCredential ParsedPublicKeyCredential
		Response                  ParsedAttestationResponse
		Raw                       CredentialCreationResponse
	}

	type args struct {
		storedChallenge    URLEncodedBase64
		verifyUser         bool
		relyingPartyID     string
		relyingPartyOrigin []string
		credParams         []CredentialParameter
	}

	testCases := []struct {
		name     string
		fields   fields
		args     args
		expected []byte
		err      string
	}{
		{
			name: "SuccessfulVerificationTest",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: string(PublicKeyCredentialType),
					},
					RawID: byteID,
				},
				Response: ParsedAttestationResponse{
					CollectedClientData: CollectedClientData{
						Type:      CeremonyType("webauthn.create"),
						Challenge: "W8GzFU8pGjhoRbWrLDlamAfq_y4S1CZG1VuoeRLARrE",
						Origin:    "https://webauthn.io",
					},
					AttestationObject: AttestationObject{
						Format:      "none",
						RawAuthData: byteAuthData,
						AuthData: AuthenticatorData{
							RPIDHash: byteRPIDHash,
							Counter:  0,
							Flags:    0x041,
							AttData: AttestedCredentialData{
								AAGUID:              make([]byte, 16),
								CredentialID:        byteID,
								CredentialPublicKey: byteCredentialPubKey,
							},
						},
					},
				},
				Raw: CredentialCreationResponse{
					PublicKeyCredential: PublicKeyCredential{
						Credential: Credential{
							Type: string(PublicKeyCredentialType),
							ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						},
						RawID: byteID,
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
				},
			},
			args: args{
				storedChallenge:    URLEncodedBase64(byteChallenge),
				verifyUser:         false,
				relyingPartyID:     `webauthn.io`,
				relyingPartyOrigin: []string{`https://webauthn.io`},
				credParams:         []CredentialParameter{{Type: "public-key", Algorithm: webauthncose.AlgES256}},
			},
			expected: []byte{0xa, 0xaf, 0x43, 0xda, 0x7e, 0xd3, 0x94, 0x98, 0x9b, 0xbc, 0x47, 0xcb, 0x0, 0x72, 0x6b, 0xbc, 0xf3, 0xa2, 0x4a, 0x49, 0x5f, 0x84, 0x4f, 0x45, 0x97, 0x91, 0x6a, 0x2d, 0xff, 0x47, 0xbc, 0xad},
			err:      "",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			pcc := &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: tc.fields.ParsedPublicKeyCredential,
				Response:                  tc.fields.Response,
				Raw:                       tc.fields.Raw,
			}

			actual, err := pcc.Verify(tc.args.storedChallenge.String(), tc.args.relyingPartyID, tc.args.relyingPartyOrigin, nil, TopOriginExplicitVerificationMode, false, tc.args.verifyUser, false, nil, tc.args.credParams)

			assert.Equal(t, tc.expected, actual)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestParseCredentialCreationResponse_NilRequest(t *testing.T) {
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
			result, err := ParseCredentialCreationResponse(tc.request)
			assert.Nil(t, result)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestCredentialCreationResponse_Parse_Errors(t *testing.T) {
	testCases := []struct {
		name string
		ccr  CredentialCreationResponse
		err  string
	}{
		{
			name: "ShouldFailMissingID",
			ccr:  CredentialCreationResponse{},
			err:  "Parse error for Registration",
		},
		{
			name: "ShouldFailIDNotBase64",
			ccr: CredentialCreationResponse{
				PublicKeyCredential: PublicKeyCredential{
					Credential: Credential{
						ID: "not valid base64 %%%",
					},
				},
			},
			err: "Parse error for Registration",
		},
		{
			name: "ShouldFailMissingType",
			ccr: CredentialCreationResponse{
				PublicKeyCredential: PublicKeyCredential{
					Credential: Credential{
						ID: "dGVzdA",
					},
				},
			},
			err: "Parse error for Registration",
		},
		{
			name: "ShouldFailBadType",
			ccr: CredentialCreationResponse{
				PublicKeyCredential: PublicKeyCredential{
					Credential: Credential{
						ID:   "dGVzdA",
						Type: "bad-type",
					},
				},
			},
			err: "Parse error for Registration",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := tc.ccr.Parse()
			assert.Nil(t, result)
			assert.EqualError(t, err, tc.err)
		})
	}
}

func TestGetAppID(t *testing.T) {
	testCases := []struct {
		name                        string
		ppkc                        ParsedPublicKeyCredential
		authExt                     AuthenticationExtensions
		credentialAttestationFormat string
		expectedAppID               string
		err                         string
	}{
		{
			name:                        "ShouldReturnEmptyWhenAuthExtNil",
			ppkc:                        ParsedPublicKeyCredential{},
			authExt:                     nil,
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			expectedAppID:               "",
		},
		{
			name:                        "ShouldReturnEmptyWhenClientExtNil",
			ppkc:                        ParsedPublicKeyCredential{},
			authExt:                     AuthenticationExtensions{ExtensionAppID: "https://example.com"},
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			expectedAppID:               "",
		},
		{
			name: "ShouldReturnEmptyWhenNotFIDOU2F",
			ppkc: ParsedPublicKeyCredential{
				ClientExtensionResults: AuthenticationExtensionsClientOutputs{
					ExtensionAppID: true,
				},
			},
			authExt:                     AuthenticationExtensions{ExtensionAppID: "https://example.com"},
			credentialAttestationFormat: "packed",
			expectedAppID:               "",
		},
		{
			name: "ShouldReturnEmptyWhenAppIDNotInClientExt",
			ppkc: ParsedPublicKeyCredential{
				ClientExtensionResults: AuthenticationExtensionsClientOutputs{
					"other": "value",
				},
			},
			authExt:                     AuthenticationExtensions{ExtensionAppID: "https://example.com"},
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			expectedAppID:               "",
		},
		{
			name: "ShouldFailWhenClientAppIDNotBool",
			ppkc: ParsedPublicKeyCredential{
				ClientExtensionResults: AuthenticationExtensionsClientOutputs{
					ExtensionAppID: "not-a-bool",
				},
			},
			authExt:                     AuthenticationExtensions{ExtensionAppID: "https://example.com"},
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			err:                         "Client Output appid did not have the expected type",
		},
		{
			name: "ShouldReturnEmptyWhenAppIDFalse",
			ppkc: ParsedPublicKeyCredential{
				ClientExtensionResults: AuthenticationExtensionsClientOutputs{
					ExtensionAppID: false,
				},
			},
			authExt:                     AuthenticationExtensions{ExtensionAppID: "https://example.com"},
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			expectedAppID:               "",
		},
		{
			name: "ShouldFailWhenSessionAppIDMissing",
			ppkc: ParsedPublicKeyCredential{
				ClientExtensionResults: AuthenticationExtensionsClientOutputs{
					ExtensionAppID: true,
				},
			},
			authExt:                     AuthenticationExtensions{},
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			err:                         "Session Data does not have an appid but Client Output indicates it should be set",
		},
		{
			name: "ShouldFailWhenSessionAppIDNotString",
			ppkc: ParsedPublicKeyCredential{
				ClientExtensionResults: AuthenticationExtensionsClientOutputs{
					ExtensionAppID: true,
				},
			},
			authExt:                     AuthenticationExtensions{ExtensionAppID: 123},
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			err:                         "Session Data appid did not have the expected type",
		},
		{
			name: "ShouldReturnAppID",
			ppkc: ParsedPublicKeyCredential{
				ClientExtensionResults: AuthenticationExtensionsClientOutputs{
					ExtensionAppID: true,
				},
			},
			authExt:                     AuthenticationExtensions{ExtensionAppID: "https://example.com"},
			credentialAttestationFormat: string(AttestationFormatFIDOUniversalSecondFactor),
			expectedAppID:               "https://example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			appID, err := tc.ppkc.GetAppID(tc.authExt, tc.credentialAttestationFormat)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tc.expectedAppID, appID)
			}
		})
	}
}

var testCredentialRequestResponses = map[string]string{
	`success`: `
{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"authenticatorAttachment":"platform",
	"clientExtensionResults":{
		"appid":true
	},
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
		"transports":["usb","nfc","fake"]
	}
}
`,
	`trailingData`: `
{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"authenticatorAttachment":"platform",
	"clientExtensionResults":{
		"appid":true
	},
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
		"transports":["usb","nfc","fake"]
	}
}

trailing
`,
	`successDeprecatedTransports`: `
{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"authenticatorAttachment":"not-valid",
	"transports":["usb","nfc","fake"],
	"clientExtensionResults":{
		"appid":true
	},
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
	}
}
`,
	`successDeprecatedTransportsAndNew`: `
{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"authenticatorAttachment":"cross-platform",
	"transports":["usb","nfc","fake"],
	"clientExtensionResults":{
		"appid":true
	},
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ",
		"transports":["usb","nfc"]
	}
}
`,
}
