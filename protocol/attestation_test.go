package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"
)

func TestAttestationVerify(t *testing.T) {
	for i := range testAttestationOptions {
		t.Run(fmt.Sprintf("Running test %d", i), func(t *testing.T) {
			options := CredentialCreation{}
			if err := json.Unmarshal([]byte(testAttestationOptions[i]), &options); err != nil {
				t.Fatal(err)
			}
			ccr := CredentialCreationResponse{}
			if err := json.Unmarshal([]byte(testAttestationResponses[i]), &ccr); err != nil {
				t.Fatal(err)
			}
			var pcc ParsedCredentialCreationData
			pcc.ID, pcc.RawID, pcc.Type, pcc.ClientExtensionResults = ccr.ID, ccr.RawID, ccr.Type, ccr.ClientExtensionResults
			pcc.Raw = ccr

			parsedAttestationResponse, err := ccr.AttestationResponse.Parse()
			if err != nil {
				t.Fatal(err)
			}

			pcc.Response = *parsedAttestationResponse

			// Test Base Verification
			err = pcc.Verify(options.Response.Challenge.String(), false, options.Response.RelyingParty.ID, options.Response.RelyingParty.Name)
			if err != nil {
				t.Fatalf("Not valid: %+v (%s)", err, err.(*Error).DevInfo)
			}
		})
	}
}

func attestationTestUnpackRequest(t *testing.T, request string) CredentialCreation {
	options := CredentialCreation{}
	if err := json.Unmarshal([]byte(request), &options); err != nil {
		t.Fatal(err)
	}
	return options
}

func attestationTestUnpackResponse(t *testing.T, response string) ParsedCredentialCreationData {
	ccr := CredentialCreationResponse{}
	if err := json.Unmarshal([]byte(response), &ccr); err != nil {
		t.Fatal(err)
	}
	var pcc ParsedCredentialCreationData
	pcc.ID, pcc.RawID, pcc.Type, pcc.ClientExtensionResults = ccr.ID, ccr.RawID, ccr.Type, ccr.ClientExtensionResults
	pcc.Raw = ccr

	parsedAttestationResponse, err := ccr.AttestationResponse.Parse()
	if err != nil {
		t.Fatal(err)
	}

	pcc.Response = *parsedAttestationResponse

	return pcc
}

func TestPackedAttestationVerification(t *testing.T) {
	t.Run("Testing Self Packed", func(t *testing.T) {
		pcc := attestationTestUnpackResponse(t, testAttestationResponses[0])

		// Test Packed Verification
		// Unpack args
		clientDataHash := sha256.Sum256(pcc.Raw.AttestationResponse.ClientDataJSON)

		_, _, err := verifyPackedFormat(pcc.Response.AttestationObject, clientDataHash[:])
		if err != nil {
			t.Fatalf("Not valid: %+v", err)
		}
	})
}

func TestTPMAttestationVerification(t *testing.T) {
	t.Run(fmt.Sprintf("Testing TPM"), func(t *testing.T) {
		pcc := attestationTestUnpackResponse(t, testAttestationTPMResponses[0])

		// Test Packed Verification
		// Unpack args
		clientDataHash := sha256.Sum256(pcc.Raw.AttestationResponse.ClientDataJSON)

		_, _, err := verifyTPMFormat(pcc.Response.AttestationObject, clientDataHash[:])
		if err != nil {
			t.Fatalf("Not valid: %+v", err)
		}
	})
}

var testAttestationOptions = []string{
	// Direct Self Attestation with EC256 - MacOS
	`{"publicKey": {
		"challenge": "rWiex8xDOPfiCgyFu4BLW6vVOmXKgPwHrlMCgEs9SBA=",
		"rp": {
		"name": "http://localhost:9005",
		"id": "localhost"
		},
		"user": {
			"name": "self",
			"displayName": "self",
			"id": "2iEAAAAAAAAAAA=="
		},
		"pubKeyCredParams": [
			{
				"type": "public-key",
				"alg": -7
			}
		],
		"authenticatorSelection": {
		"authenticatorAttachment": "cross-platform",
		"userVerification": "preferred"
		},
		"timeout": 60000,
		"attestation": "direct"
	}}`,
	// Direct Attestation with EC256
	`{"publicKey": {
		"challenge": "+Ri5NZTzJ8b6mvW3TVScLotEoALfgBa2Bn4YSaIObHc=",
		"rp": {
		"name": "https://webauthn.io",
		"id": "webauthn.io"
		},
		"user": {
			"name": "flort",
			"displayName": "flort",
			"id": "1DMAAAAAAAAAAA=="
		},
		"pubKeyCredParams": [
			{
				"type": "public-key",
				"alg": -7
			}
		],
		"authenticatorSelection": {
		"authenticatorAttachment": "cross-platform",
		"userVerification": "preferred"
		},
		"timeout": 60000,
		"attestation": "direct"
	}}`,
	// None Attestation with EC256
	`{
		"publicKey": {
		  "challenge": "sVt4ScceMzqFSnfAq8hgLzblvo3fa4/aFVEcIESHIJ0=",
		  "rp": {
			"name": "https://webauthn.io",
			"id": "webauthn.io"
		  },
		  "user": {
			"name": "testuser1",
			"displayName": "testuser1",
			"id": "1zMAAAAAAAAAAA=="
		  },
		  "pubKeyCredParams": [
			{
			  "type": "public-key",
			  "alg": -7
			}
		  ],
		  "authenticatorSelection": {
			"authenticatorAttachment": "cross-platform",
			"userVerification": "preferred"
		  },
		  "timeout": 60000,
		  "attestation": "none"
		}
	  }`,
}

var testAttestationResponses = []string{
	// Self Attestation with EC256 - MacOS
	`{ 
		"id": "AOx6vFGGITtlwjhqFFvAkJmBzSzfwE1dBa1fVR_Ltq5L35FJRNdgkXe84v3-0TEVNCSp",
		"rawId": "AOx6vFGGITtlwjhqFFvAkJmBzSzfwE1dBa1fVR_Ltq5L35FJRNdgkXe84v3-0TEVNCSp",
		"response": {
			"attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhAJgdgw5x8JzE4JfR6x1RBO8eCHNE8eW_L1VTV03zpyL5AiBv8eUzua3XSS3bPYC7m8eXzJhcaRyeGe7UcuqIrDSvC2hhdXRoRGF0YVi3SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFXJE5zK3OAAI1vMYKZIsLJfHwVQMAMwDserxRhiE7ZcI4ahRbwJCZgc0s38BNXQWtX1Ufy7auS9-RSUTXYJF3vOL9_tExFTQkqaUBAgMmIAEhWCCm9OYidwiIoH9SwVQqUAnH8Gj5ZJ2_qr8gjbg41q4M1SJYIA07XKpHSgS1mE7R1MjotVIQqyHi9WAxGwHQsCteVK2V",
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJyV2lleDh4RE9QZmlDZ3lGdTRCTFc2dlZPbVhLZ1B3SHJsTUNnRXM5U0JBIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo5MDA1IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
		},
		"type": "public-key"
	}`,
	// Direct Attestation with EC256 - Titan
	`{ 
		"id": "FOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmg",
		"rawId": "FOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmg",
		"response": {
			"attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgfyIhwZj-fkEVyT1GOK8chDHJR2chXBLSRg6bTCjODmwCIHH6GXI_BQrcR-GHg5JfazKVQdezp6_QWIFfT4ltTCO2Y3g1Y4FZAlMwggJPMIIBN6ADAgECAgQSNtF_MA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAxMS8wLQYDVQQDDCZZdWJpY28gVTJGIEVFIFNlcmlhbCAyMzkyNTczNDEwMzI0MTA4NzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNNlqR5emeDVtDnA2a-7h_QFjkfdErFE7bFNKzP401wVE-QNefD5maviNnGVk4HJ3CsHhYuCrGNHYgTM9zTWriGjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQAiG5uzsnIk8T6-oyLwNR6vRklmo29yaYV8jiP55QW1UnXdTkEiPn8mEQkUac-Sn6UmPmzHdoGySG2q9B-xz6voVQjxP2dQ9sgbKd5gG15yCLv6ZHblZKkdfWSrUkrQTrtaziGLFSbxcfh83vUjmOhDLFC5vxV4GXq2674yq9F2kzg4nCS4yXrO4_G8YWR2yvQvE2ffKSjQJlXGO5080Ktptplv5XN4i5lS-AKrT5QRVbEJ3B4g7G0lQhdYV-6r4ZtHil8mF4YNMZ0-RaYPxAaYNWkFYdzOZCaIdQbXRZefgGfbMUiAC2gwWN7fiPHV9eu82NYypGU32OijG9BjhGt_aGF1dGhEYXRhWMR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EEAAAAAAAAAAAAAAAAAAAAAAAAAAABAFOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmqUBAgMmIAEhWCD_ap3Q9zU8OsGe967t48vyRxqn8NfFTk307mC1WsH2ISJYIIcqAuW3MxhU0uDtaSX8-Ftf_zeNJLdCOEjZJGHsrLxH",
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiItUmk1TlpUeko4YjZtdlczVFZTY0xvdEVvQUxmZ0JhMkJuNFlTYUlPYkhjIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		},
		"type": "public-key"
	}`,
	// None Attestation with EC256 - Titan
	`{
		"id": "6Jry73M_WVWDoXLsGxRsBVVHpPWDpNy1ETGXUEvJLdTAn5Ew6nDGU6W8iO3ZkcLEqr-CBwvx0p2WAxzt8RiwQQ",
		"rawId": "6Jry73M_WVWDoXLsGxRsBVVHpPWDpNy1ETGXUEvJLdTAn5Ew6nDGU6W8iO3ZkcLEqr-CBwvx0p2WAxzt8RiwQQ",
		"response": {
			"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOia8u9zP1lVg6Fy7BsUbAVVR6T1g6TctRExl1BLyS3UwJ-RMOpwxlOlvIjt2ZHCxKq_ggcL8dKdlgMc7fEYsEGlAQIDJiABIVgg--n_QvZithDycYmnifk6vMHiwBP6kugn2PlsnvkrcSgiWCBAlBYm2B-rMtQlp5MxGTLoGDHoktxb0p364Hy2BH9U2Q",
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJzVnQ0U2NjZU16cUZTbmZBcThoZ0x6Ymx2bzNmYTRfYUZWRWNJRVNISUowIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		},
		"type": "public-key"
	}`,
}

var testAttestationTPMResponses = []string{
	// TPM attestation with ECC
	`{
               "id": "hsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnQ",
               "rawId": "hsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnQ",
               "type": "public-key",
               "response": {
                       "attestationObject": "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQCqAcGoi2IFXCF5xxokjR5yOAwK_11iCOqt8hCkpHE9rW602J3KjhcRQzoFf1UxZvadwmYcHHMxDQDmVuOhH-yW-DfARVT7O3MzlhhzrGTNO_-jhGFsGeEdz0RgNsviDdaVP5lNsV6Pe4bMhgBv1aTkk0zx1T8sxK8B7gKT6x80RIWg89_aYY4gHR4n65SRDp2gOGI2IHDvqTwidyeaAHVPbDrF8iDbQ88O-GH_fheAtFtgjbIq-XQbwVdzQhYdWyL0XVUwGLSSuABuB4seRPkyZCKoOU6VuuQzfWNpH2Nl05ybdXi27HysUexgfPxihB3PbR8LJdi1j04tRg3JvBUvY3ZlcmMyLjBjeDVjglkFuzCCBbcwggOfoAMCAQICEGEZiaSlAkKpqaQOKDYmWPkwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLU5UQy1LRVlJRC1FNEE4NjY2RjhGNEM2RDlDMzkzMkE5NDg4NDc3ODBBNjgxMEM0MjEzMB4XDTIyMDExMjIyMTUxOFoXDTI3MDYxMDE4NTQzNlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKo-7DHdiipZTzfA9fpTaIMVK887zM0nXAVIvU0kmGAsPpTYbf7dn1DAl6BhcDkXs2WrwYP02K8RxXWOF4jf7esMAIkr65zPWqLys8WRNM60d7g9GOADwbN8qrY0hepSsaJwjhswbNJI6L8vJwnnrQ6UWVCm3xHqn8CB2iSWNSUnshgTQTkJ1ZEdToeD51sFXUE0fSxXjyIiSAAD4tCIZkmHFVqchzfqUgiiM_mbbKzUnxEZ6c6r39ccHzbm4Ir-u62repQnVXKTpzFBbJ-Eg15REvw6xuYaGtpItk27AXVcEodfAylf7pgQPfExWkoMZfb8faqbQAj5x29mBJvlzj0CAwEAAaOCAeowggHmMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMFAGA1UdEQEB_wRGMESkQjBAMT4wEAYFZ4EFAgIMB05QQ1Q3NXgwFAYFZ4EFAgEMC2lkOjRFNTQ0MzAwMBQGBWeBBQIDDAtpZDowMDA3MDAwMjAfBgNVHSMEGDAWgBQ3yjAtSXrnaSNOtzy1PEXxOO1ZUDAdBgNVHQ4EFgQU1ml3H5Tzrs0Nev69tFNhPZnhaV0wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1udGMta2V5aWQtZTRhODY2NmY4ZjRjNmQ5YzM5MzJhOTQ4ODQ3NzgwYTY4MTBjNDIxMy9lMDFjMjA2Mi1mYmRjLTQwYTUtYTQwZi1jMzc3YzBmNzY1MWMuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQAz-YGrj0S841gyMZuit-qsKpKNdxbkaEhyB1baexHGcMzC2y1O1kpTrpaH3I80hrIZFtYoA2xKQ1j67uoC6vm1PhsJB6qhs9T7zmWZ1VtleJTYGNZ_bYY2wo65qJHFB5TXkevJUVe2G39kB_W1TKB6g_GSwb4a5e4D_Sjp7b7RZpyIKHT1_UE1H4RXgR9Qi68K4WVaJXJUS6T4PHrRc4PeGUoJLQFUGxYokWIf456G32GwGgvUSX76K77pVv4Y-kT3v5eEJdYxlS4EVT13a17KWd0DdLje0Ae69q_DQSlrHVLUrADvuZMeM8jxyPQvDb7ETKLsSUeHm73KOCGLStcGQ3pB49nt3d9XdWCcUwUrmbBF2G7HsRgTNbj16G6QUcWroQEqNrBG49aO9mMZ0NwSn5d3oNuXSXjLdGBXM1ukLZ-GNrZDYw5KXU102_5VpHpjIHrZh0dXg3Q9eucKe6EkFbH65-O5VaQWUnR5WJpt6-fl_l0iHqHnKXbgL6tjeerCqZWDvFsOak05R-hosAoQs_Ni0EsgZqHwR_VlG86fsSwCVU3_sDKTNs_Je08ewJ_bbMB5Tq6k1Sxs8Aw8R96EwjQLp3z-Zva1myU-KerYYVDl5BdvgPqbD8Xmst-z6vrP3CJbtr8jgqVS7RWy_cJOA8KCZ6IS_75QT7Gblq6UGFkG7zCCBuswggTToAMCAQICEzMAAAbTtnznKsOrB-gAAAAABtMwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MTAxODU0MzZaFw0yNzA2MTAxODU0MzZaMEExPzA9BgNVBAMTNkVVUy1OVEMtS0VZSUQtRTRBODY2NkY4RjRDNkQ5QzM5MzJBOTQ4ODQ3NzgwQTY4MTBDNDIxMzCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAJA7GLwHWWbn2H8DRppxQfre4zll1sgE3Wxt9DTYWt5-v-xKwCQb6z_7F1py7LMe58qLqglAgVhS6nEvN2puZ1GzejdsFFxz2gyEfH1y-X3RGp0dxS6UKwEtmksaMEKIRQn2GgKdUkiuvkaxaoznuExoTPyu0aXk6yFsX5KEDu9UZCgt66bRy6m3KIRnn1VK2frZfqGYi8C8x9Q69oGG316tUwAIm3ypDtv3pREXsDLYE1U5Irdv32hzJ4CqqPyau-qJS18b8CsjvgOppwXRSwpOmU7S3xqo-F7h1eeFw2tgHc7PEPt8MSSKeba8Fz6QyiLhgFr8jFUvKRzk4B41HFUMqXYawbhAtfIBiGGsGrrdNKb7MxISnH1E6yLVCQGGhXiN9U7V0h8Gn56eKzopGlubw7yMmgu8Cu2wBX_a_jFmIBHnn8YgwcRm6NvT96KclDHnFqPVm3On12bG31F7EYkIRGLbaTT6avEu9rL6AJn7Xr245Sa6dC_OSMRKqLSufxp6O6f2TH2g4kvT0Go9SeyM2_acBjIiQ0rFeBOm49H4E4VcJepf79FkljovD68imeZ5MXjxepcCzS138374Jeh7k28JePwJnjDxS8n9Dr6xOU3_wxS1gN5cW6cXSoiPGe0JM4CEyAcUtKrvpUWoTajxxnylZuvS8ou2thfH2PQlAgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBQ3yjAtSXrnaSNOtzy1PEXxOO1ZUDAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAFZTSitCISvll6i6rPUPd8Wt2mogRw6I_c-dWQzdc9-SY9iaIGXqVSPKKOlAYU2ju7nvN6AvrIba6sngHeU0AUTeg1UZ5-bDFOWdSgPaGyH_EN_l-vbV6SJPzOmZHJOHfw2WT8hjlFaTaKYRXxzFH7PUR4nxGRbWtdIGgQhUlWg5oo_FO4bvLKfssPSONn684qkAVierq-ly1WeqJzOYhd4EylgVJ9NL3YUhg8dYcHAieptDzF7OcDqffbuZLZUx6xcyibhWQcntAh7a3xPwqXxENsHhme_bqw_kqa-NVk-Wz4zdoiNNLRvUmCSL1WLc4JPsFJ08Ekn1kW7f9ZKnie5aw-29jEf6KIBt4lGDD3tXTfaOVvWcDbu92jMOO1dhEIj63AwQiDJgZhqnrpjlyWU_X0IVQlaPBg80AE0Y3sw1oMrY0XwdeQUjSpH6e5fTYKrNB6NMT1jXGjKIzVg8XbPWlnebP2wEhq8rYiDR31b9B9Sw_naK7Xb-Cqi-VQdUtknSjeljusrBpxGUx-EIJci0-dzeXRT5_376vyKSuYxA1Xd2jd4EknJLIAVLT3rb10DCuKGLDgafbsfTBxVoEa9hSjYOZUr_m3WV6t6I9WPYjVyhyi7fCEIG4JE7YbM4na4jg5q3DM8ibE8jyufAq0PfJZTJyi7c2Q2N_9NgnCNwZ3B1YkFyZWFYdgAjAAsABAByACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAAAwAQACAek7g2C8TeORRoKxuN7HrJ5OinVGuHzEgYODyUsF9D1wAggXPPXn-Pm_4IF0c4XVaJjmHO3EB2KBwdg_L60N0IL9xoY2VydEluZm9Yof9UQ0eAFwAiAAvQNGTLa2wT6u8SKDDdwkgaq5Cmh6jcD_6ULvM9ZmvdbwAUtMInD3WtGSdWHPWijMrW_TfYo-gAAAABPuBems3Sywu4aQsGAe85iOosjtXIACIAC5FPRiZSJzjYMNnAz9zFtM62o57FJwv8F5gNEcioqhHwACIACyVXxq1wZhDsqTqdYr7vQUUJ3vwWVrlN0ZQv5HFnHqWdaGF1dGhEYXRhWKR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EUAAAAACJhwWMrcS4G24TDeUNy-lgAghsS2ywFz_LWf9-lC35vC9uJTVD3ZCVdweZvESUbjXnSlAQIDJiABIVggHpO4NgvE3jkUaCsbjex6yeTop1Rrh8xIGDg8lLBfQ9ciWCCBc89ef4-b_ggXRzhdVomOYc7cQHYoHB2D8vrQ3Qgv3A",
                       "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoidXpuOXUwVHgtTEJkdEdnRVJzYmtIUkJqaVV0NWkycnZtMkJCVFpyV3FFbyIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uaW8iLCJjcm9zc09yaWdpbiI6ZmFsc2V9"
               }
       }`,
}
