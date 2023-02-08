package protocol

import (
	"bytes"
	"encoding/base64"
	"io/ioutil"
	"net/http"
	"reflect"
	"testing"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestParseCredentialCreationResponse(t *testing.T) {
	reqBody := ioutil.NopCloser(bytes.NewReader([]byte(testCredentialRequestBody)))
	httpReq := &http.Request{Body: reqBody}
	type args struct {
		response *http.Request
	}

	byteID, _ := base64.RawURLEncoding.DecodeString("6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteRPIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pSJYIMfCKfxl2SvnqJIiHQysHmpmITNgtCkQ5ESExSRjqrhXAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNc")
	byteAttObject, _ := base64.RawURLEncoding.DecodeString("o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ")

	tests := []struct {
		name    string
		args    args
		want    *ParsedCredentialCreationData
		wantErr bool
	}{
		{
			name: "Successful Credential Request Parsing",
			args: args{
				response: httpReq,
			},
			want: &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: "public-key",
					},
					RawID: byteID,
					ClientExtensionResults: AuthenticationExtensionsClientOutputs{
						"appid": true,
					},
				},
				Transports: []AuthenticatorTransport{USB, NFC, "fake"},
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
							Type: "public-key",
							ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						},
						RawID: byteID,
						ClientExtensionResults: AuthenticationExtensionsClientOutputs{
							"appid": true,
						},
					},
					AttestationResponse: AuthenticatorAttestationResponse{
						AuthenticatorResponse: AuthenticatorResponse{
							ClientDataJSON: byteClientDataJSON,
						},
						AttestationObject: byteAttObject,
					},
					Transports: []string{"usb", "nfc", "fake"},
				},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialCreationResponse(tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialCreationResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.ClientExtensionResults, tt.want.ClientExtensionResults) {
				t.Errorf("Extensions = %v \n want: %v", got.ClientExtensionResults, tt.want.ClientExtensionResults)
			}
			if !reflect.DeepEqual(got.Transports, tt.want.Transports) {
				t.Errorf("Transports = %v \n want: %v", got.Transports, tt.want.Transports)
			}
			if !reflect.DeepEqual(got.ID, tt.want.ID) {
				t.Errorf("ID = %v \n want: %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.ParsedCredential, tt.want.ParsedCredential) {
				t.Errorf("ParsedCredential = %v \n want: %v", got.ParsedCredential, tt.want.ParsedCredential)
			}
			if !reflect.DeepEqual(got.ParsedPublicKeyCredential, tt.want.ParsedPublicKeyCredential) {
				t.Errorf("ParsedPublicKeyCredential = %v \n want: %v", got.ParsedPublicKeyCredential, tt.want.ParsedPublicKeyCredential)
			}
			if !reflect.DeepEqual(got.Raw, tt.want.Raw) {
				t.Errorf("Raw = %v \n want: %v", got.Raw, tt.want.Raw)
			}
			if !reflect.DeepEqual(got.RawID, tt.want.RawID) {
				t.Errorf("RawID = %v \n want: %v", got.RawID, tt.want.RawID)
			}
			// Unmarshall CredentialPublicKey
			var pkWant interface{}
			keyBytesWant := tt.want.Response.AttestationObject.AuthData.AttData.CredentialPublicKey
			webauthncbor.Unmarshal(keyBytesWant, &pkWant)
			var pkGot interface{}
			keyBytesGot := got.Response.AttestationObject.AuthData.AttData.CredentialPublicKey
			webauthncbor.Unmarshal(keyBytesGot, &pkGot)
			if !reflect.DeepEqual(pkGot, pkWant) {
				t.Errorf("Response = %+v \n want: %+v", pkGot, pkWant)
			}
			if !reflect.DeepEqual(got.Type, tt.want.Type) {
				t.Errorf("Type = %v \n want: %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.Response.CollectedClientData, tt.want.Response.CollectedClientData) {
				t.Errorf("CollectedClientData = %v \n want: %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.Response.AttestationObject.Format, tt.want.Response.AttestationObject.Format) {
				t.Errorf("Format = %v \n want: %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.Response.AttestationObject.AuthData.AttData.CredentialID, tt.want.Response.AttestationObject.AuthData.AttData.CredentialID) {
				t.Errorf("CredentialID = %v \n want: %v", got, tt.want)
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
		storedChallenge    Challenge
		verifyUser         bool
		relyingPartyID     string
		relyingPartyOrigin []string
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "Successful Verification Test",
			fields: fields{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
						Type: "public-key",
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
							Type: "public-key",
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
				storedChallenge:    byteChallenge,
				verifyUser:         false,
				relyingPartyID:     `webauthn.io`,
				relyingPartyOrigin: []string{`https://webauthn.io`},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pcc := &ParsedCredentialCreationData{
				ParsedPublicKeyCredential: tt.fields.ParsedPublicKeyCredential,
				Response:                  tt.fields.Response,
				Raw:                       tt.fields.Raw,
			}
			if err := pcc.Verify(tt.args.storedChallenge.String(), tt.args.verifyUser, tt.args.relyingPartyID, tt.args.relyingPartyOrigin); (err != nil) != tt.wantErr {
				t.Errorf("ParsedCredentialCreationData.Verify() error = %+v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

var testCredentialRequestBody = `{
	"id":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"rawId":"6xrtBhJQW6QU4tOaB4rrHaS2Ks0yDDL_q8jDC16DEjZ-VLVf4kCRkvl2xp2D71sTPYns-exsHQHTy3G-zJRK8g",
	"type":"public-key",
	"transports":["usb","nfc","fake"],
	"clientExtensionResults":{
		"appid":true
	},
	"response":{
		"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOsa7QYSUFukFOLTmgeK6x2ktirNMgwy_6vIwwtegxI2flS1X-JAkZL5dsadg-9bEz2J7PnsbB0B08txvsyUSvKlAQIDJiABIVggLKF5xS0_BntttUIrm2Z2tgZ4uQDwllbdIfrrBMABCNciWCDHwin8Zdkr56iSIh0MrB5qZiEzYLQpEOREhMUkY6q4Vw",
		"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJXOEd6RlU4cEdqaG9SYldyTERsYW1BZnFfeTRTMUNaRzFWdW9lUkxBUnJFIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		}
	}`
