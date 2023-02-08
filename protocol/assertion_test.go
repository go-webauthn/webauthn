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

func TestParseCredentialRequestResponse(t *testing.T) {
	reqBody := ioutil.NopCloser(bytes.NewReader([]byte(testAssertionResponses["success"])))
	httpReq := &http.Request{Body: reqBody}

	byteID, _ := base64.RawURLEncoding.DecodeString("AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng")
	byteAAGUID, _ := base64.RawURLEncoding.DecodeString("rc4AAjW8xgpkiwsl8fBVAw")
	byteRPIDHash, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvA")
	byteAuthData, _ := base64.RawURLEncoding.DecodeString("dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ")
	byteSignature, _ := base64.RawURLEncoding.DecodeString("MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc")
	byteUserHandle, _ := base64.RawURLEncoding.DecodeString("0ToAAAAAAAAAAA")
	byteCredentialPubKey, _ := base64.RawURLEncoding.DecodeString("pQMmIAEhWCAoCF-x0dwEhzQo-ABxHIAgr_5WL6cJceREc81oIwFn7iJYIHEHx8ZhBIE42L26-rSC_3l0ZaWEmsHAKyP9rgslApUdAQI")
	byteClientDataJSON, _ := base64.RawURLEncoding.DecodeString("eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9")

	type args struct {
		response *http.Request
	}
	tests := []struct {
		name    string
		args    args
		want    *ParsedCredentialAssertionData
		wantErr bool
	}{
		{
			name: "Successfully Parse Credential Assertion",
			args: args{
				httpReq,
			},
			want: &ParsedCredentialAssertionData{
				ParsedPublicKeyCredential: ParsedPublicKeyCredential{
					ParsedCredential: ParsedCredential{
						ID:   "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
						Type: "public-key",
					},
					RawID: byteID,
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
							Type: "public-key",
							ID:   "AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
						},
						RawID: byteID,
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
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := ParseCredentialRequestResponse(tt.args.response)
			if (err != nil) != tt.wantErr {
				t.Errorf("ParseCredentialRequestResponse() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got.ClientExtensionResults, tt.want.ClientExtensionResults) {
				t.Errorf("ClientExtensionResults = %v \n want: %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.ID, tt.want.ID) {
				t.Errorf("ID = %v \n want: %v", got.ID, tt.want.ID)
			}
			if !reflect.DeepEqual(got.ParsedCredential, tt.want.ParsedCredential) {
				t.Errorf("ParsedCredential = %v \n want: %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.ParsedPublicKeyCredential, tt.want.ParsedPublicKeyCredential) {
				t.Errorf("ParsedPublicKeyCredential = %v \n want: %v", got.ParsedPublicKeyCredential.ClientExtensionResults, tt.want.ParsedPublicKeyCredential.ClientExtensionResults)
			}
			if !reflect.DeepEqual(got.Raw, tt.want.Raw) {
				t.Errorf("Raw = %+v \n want: %+v", got.Raw, tt.want.Raw)
			}
			if !reflect.DeepEqual(got.RawID, tt.want.RawID) {
				t.Errorf("RawID = %v \n want: %v", got, tt.want)
			}
			if !reflect.DeepEqual(got.Response, tt.want.Response) {
				var pkInterfaceMismatch bool
				if !reflect.DeepEqual(got.Response.CollectedClientData, tt.want.Response.CollectedClientData) {
					t.Errorf("Collected Client Data = %v \n want: %v", got.Response.CollectedClientData, tt.want.Response.CollectedClientData)
				}
				if !reflect.DeepEqual(got.Response.Signature, tt.want.Response.Signature) {
					t.Errorf("Signature = %v \n want: %v", got.Response.Signature, tt.want.Response.Signature)
				}
				if !reflect.DeepEqual(got.Response.AuthenticatorData.AttData.CredentialPublicKey, tt.want.Response.AuthenticatorData.AttData.CredentialPublicKey) {
					// Unmarshall CredentialPublicKey
					var pkWant interface{}
					keyBytesWant := tt.want.Response.AuthenticatorData.AttData.CredentialPublicKey
					webauthncbor.Unmarshal(keyBytesWant, &pkWant)
					var pkGot interface{}
					keyBytesGot := got.Response.AuthenticatorData.AttData.CredentialPublicKey
					webauthncbor.Unmarshal(keyBytesGot, &pkGot)
					if !reflect.DeepEqual(pkGot, pkWant) {
						t.Errorf("Response = %+v \n want: %+v", pkGot, pkWant)
					} else {
						pkInterfaceMismatch = true
					}
				}
				if pkInterfaceMismatch {
					return
				} else {
					t.Errorf("Response = %+v \n want: %+v", got.Response, tt.want.Response)
				}
			}
		})
	}
}

func TestParsedCredentialAssertionData_Verify(t *testing.T) {
	type fields struct {
		ParsedPublicKeyCredential ParsedPublicKeyCredential
		Response                  ParsedAssertionResponse
		Raw                       CredentialAssertionResponse
	}
	type args struct {
		storedChallenge    Challenge
		relyingPartyID     string
		relyingPartyOrigin []string
		verifyUser         bool
		credentialBytes    []byte
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		// TODO: Add test cases.
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := &ParsedCredentialAssertionData{
				ParsedPublicKeyCredential: tt.fields.ParsedPublicKeyCredential,
				Response:                  tt.fields.Response,
				Raw:                       tt.fields.Raw,
			}

			if err := p.Verify(tt.args.storedChallenge.String(), tt.args.relyingPartyID, tt.args.relyingPartyOrigin, "", tt.args.verifyUser, tt.args.credentialBytes); (err != nil) != tt.wantErr {
				t.Errorf("ParsedCredentialAssertionData.Verify() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

var testAssertionOptions = map[string]string{
	// None Attestation - MacOS TouchID
	`success`: `{
		"id":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"rawId":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"type":"public-key",
		"response":{
			"attestationObject":"o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVi7dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiFa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
			"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJmeWV1dUdQOXp1ZWoyRkdqZXZpNzlienFNS1d4aTRQWUlhXzV3ajI2MVcwIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"}
		}
	`,
}

var testAssertionResponses = map[string]string{
	// None Attestation - MacOS TouchID
	`success`: `{
		"id":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"rawId":"AI7D5q2P0LS-Fal9ZT7CHM2N5BLbUunF92T8b6iYC199bO2kagSuU05-5dZGqb1SP0A0lyTWng",
		"type":"public-key",
		"response":{
			"authenticatorData":"dKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBFXJJiGa3OAAI1vMYKZIsLJfHwVQMANwCOw-atj9C0vhWpfWU-whzNjeQS21Lpxfdk_G-omAtffWztpGoErlNOfuXWRqm9Uj9ANJck1p6lAQIDJiABIVggKAhfsdHcBIc0KPgAcRyAIK_-Vi-nCXHkRHPNaCMBZ-4iWCBxB8fGYQSBONi9uvq0gv95dGWlhJrBwCsj_a4LJQKVHQ",
			"clientDataJSON":"eyJjaGFsbGVuZ2UiOiJFNFBUY0lIX0hmWDFwQzZTaWdrMVNDOU5BbGdlenROMDQzOXZpOHpfYzlrIiwibmV3X2tleXNfbWF5X2JlX2FkZGVkX2hlcmUiOiJkbyBub3QgY29tcGFyZSBjbGllbnREYXRhSlNPTiBhZ2FpbnN0IGEgdGVtcGxhdGUuIFNlZSBodHRwczovL2dvby5nbC95YWJQZXgiLCJvcmlnaW4iOiJodHRwczovL3dlYmF1dGhuLmlvIiwidHlwZSI6IndlYmF1dGhuLmdldCJ9",
			"signature":"MEUCIBtIVOQxzFYdyWQyxaLR0tik1TnuPhGVhXVSNgFwLmN5AiEAnxXdCq0UeAVGWxOaFcjBZ_mEZoXqNboY5IkQDdlWZYc",
			"userHandle":"0ToAAAAAAAAAAA"}
		}
	`,
}
