package protocol

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/go-webauthn/webauthn/metadata"
)

func TestAttestationVerify(t *testing.T) {
	if err := metadata.PopulateMetadata(metadata.ProductionMDSURL); err != nil {
		t.Fatal(err)
	}

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
			err = pcc.Verify(options.Response.Challenge.String(), false, options.Response.RelyingParty.ID, []string{options.Response.RelyingParty.Name})
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

func attestationTestUnpackResponse(t *testing.T, response string) (pcc ParsedCredentialCreationData) {
	ccr := CredentialCreationResponse{}
	if err := json.Unmarshal([]byte(response), &ccr); err != nil {
		t.Fatal(err)
	}

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

		// Test Packed Verification. Unpack args.
		clientDataHash := sha256.Sum256(pcc.Raw.AttestationResponse.ClientDataJSON)

		_, _, err := verifyPackedFormat(pcc.Response.AttestationObject, clientDataHash[:])
		if err != nil {
			t.Fatalf("Not valid: %+v", err)
		}
	})
}

var testAttestationOptions = []string{
	// Direct Self Attestation with EC256 - MacOS.
	`{"publicKey": {
		"challenge": "rWiex8xDOPfiCgyFu4BLW6vVOmXKgPwHrlMCgEs9SBA",
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
	// Direct Attestation with EC256.
	`{"publicKey": {
		"challenge": "-Ri5NZTzJ8b6mvW3TVScLotEoALfgBa2Bn4YSaIObHc",
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
	// None Attestation with EC256.
	`{
		"publicKey": {
		  "challenge": "sVt4ScceMzqFSnfAq8hgLzblvo3fa4_aFVEcIESHIJ0",
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
	// TPM Attestation from Windows Hello Hardware AAGUID
	`{
		"publicKey": {
			"rp": {
				"name": "https://webauthn.firstyear.id.au",
				"id": "webauthn.firstyear.id.au"
			},
			"user": {
				"id": "Mhi6ldkISTGNAmP7pzZfIA",
				"name": "compatuser",
				"displayName": "compatuser"
			},
			"challenge": "E2YebMmG9992XialpFL1lkPptOIBPeKsphNkt1JcbKk",
			"pubKeyCredParams": [
				{ "type": "public-key", "alg": -7 },
				{ "type": "public-key", "alg": -35 },
				{ "type": "public-key", "alg": -36 },
				{ "type": "public-key", "alg": -257 },
				{ "type": "public-key", "alg": -258 },
				{ "type": "public-key", "alg": -259 },
				{ "type": "public-key", "alg": -37 },
				{ "type": "public-key", "alg": -38 },
				{ "type": "public-key", "alg": -39 },
				{ "type": "public-key", "alg": -8 },
				{ "type": "public-key", "alg": -65535 }
			],
			"timeout": 60000,
			"attestation": "direct",
			"authenticatorSelection": {
				"requireResidentKey": false,
				"userVerification": "discouraged"
			},
			"extensions": {
				"credentialProtectionPolicy": "userVerificationOptionalWithCredentialIDList",
				"enforceCredentialProtectionPolicy": false,
				"uvm": true,
				"credProps": true,
				"minPinLength": true,
				"hmacCreateSecret": true
			}
			}
	}`,
}

var testAttestationResponses = []string{
	// Self Attestation with EC256 - MacOS.
	`{ 
		"id": "AOx6vFGGITtlwjhqFFvAkJmBzSzfwE1dBa1fVR_Ltq5L35FJRNdgkXe84v3-0TEVNCSp",
		"rawId": "AOx6vFGGITtlwjhqFFvAkJmBzSzfwE1dBa1fVR_Ltq5L35FJRNdgkXe84v3-0TEVNCSp",
		"response": {
			"attestationObject": "o2NmbXRmcGFja2VkZ2F0dFN0bXSiY2FsZyZjc2lnWEcwRQIhAJgdgw5x8JzE4JfR6x1RBO8eCHNE8eW_L1VTV03zpyL5AiBv8eUzua3XSS3bPYC7m8eXzJhcaRyeGe7UcuqIrDSvC2hhdXRoRGF0YVi3SZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NFXJE5zK3OAAI1vMYKZIsLJfHwVQMAMwDserxRhiE7ZcI4ahRbwJCZgc0s38BNXQWtX1Ufy7auS9-RSUTXYJF3vOL9_tExFTQkqaUBAgMmIAEhWCCm9OYidwiIoH9SwVQqUAnH8Gj5ZJ2_qr8gjbg41q4M1SJYIA07XKpHSgS1mE7R1MjotVIQqyHi9WAxGwHQsCteVK2V",
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJyV2lleDh4RE9QZmlDZ3lGdTRCTFc2dlZPbVhLZ1B3SHJsTUNnRXM5U0JBIiwib3JpZ2luIjoiaHR0cDovL2xvY2FsaG9zdDo5MDA1IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9"
		},
		"type": "public-key"
	}`,
	// Direct Attestation with EC256 - Titan.
	`{ 
		"id": "FOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmg",
		"rawId": "FOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmg",
		"response": {
			"attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEYwRAIgfyIhwZj-fkEVyT1GOK8chDHJR2chXBLSRg6bTCjODmwCIHH6GXI_BQrcR-GHg5JfazKVQdezp6_QWIFfT4ltTCO2Y3g1Y4FZAlMwggJPMIIBN6ADAgECAgQSNtF_MA0GCSqGSIb3DQEBCwUAMC4xLDAqBgNVBAMTI1l1YmljbyBVMkYgUm9vdCBDQSBTZXJpYWwgNDU3MjAwNjMxMCAXDTE0MDgwMTAwMDAwMFoYDzIwNTAwOTA0MDAwMDAwWjAxMS8wLQYDVQQDDCZZdWJpY28gVTJGIEVFIFNlcmlhbCAyMzkyNTczNDEwMzI0MTA4NzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABNNlqR5emeDVtDnA2a-7h_QFjkfdErFE7bFNKzP401wVE-QNefD5maviNnGVk4HJ3CsHhYuCrGNHYgTM9zTWriGjOzA5MCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS41MBMGCysGAQQBguUcAgEBBAQDAgUgMA0GCSqGSIb3DQEBCwUAA4IBAQAiG5uzsnIk8T6-oyLwNR6vRklmo29yaYV8jiP55QW1UnXdTkEiPn8mEQkUac-Sn6UmPmzHdoGySG2q9B-xz6voVQjxP2dQ9sgbKd5gG15yCLv6ZHblZKkdfWSrUkrQTrtaziGLFSbxcfh83vUjmOhDLFC5vxV4GXq2674yq9F2kzg4nCS4yXrO4_G8YWR2yvQvE2ffKSjQJlXGO5080Ktptplv5XN4i5lS-AKrT5QRVbEJ3B4g7G0lQhdYV-6r4ZtHil8mF4YNMZ0-RaYPxAaYNWkFYdzOZCaIdQbXRZefgGfbMUiAC2gwWN7fiPHV9eu82NYypGU32OijG9BjhGt_aGF1dGhEYXRhWMR0puqSE8mcL3SyJJKzIM9AJiqUwalQoDl_KSULYIQe8EEAAAAAAAAAAAAAAAAAAAAAAAAAAABAFOxcmsqPLNCHtyILvbNkrtHMdKAeqSJXYZDbeFd0kc5Enm8Kl6a0Jp0szgLilDw1S4CjZhe9Z2611EUGbjyEmqUBAgMmIAEhWCD_ap3Q9zU8OsGe967t48vyRxqn8NfFTk307mC1WsH2ISJYIIcqAuW3MxhU0uDtaSX8-Ftf_zeNJLdCOEjZJGHsrLxH",
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiItUmk1TlpUeko4YjZtdlczVFZTY0xvdEVvQUxmZ0JhMkJuNFlTYUlPYkhjIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		},
		"type": "public-key"
	}`,
	// None Attestation with EC256 - Titan.
	`{
		"id": "6Jry73M_WVWDoXLsGxRsBVVHpPWDpNy1ETGXUEvJLdTAn5Ew6nDGU6W8iO3ZkcLEqr-CBwvx0p2WAxzt8RiwQQ",
		"rawId": "6Jry73M_WVWDoXLsGxRsBVVHpPWDpNy1ETGXUEvJLdTAn5Ew6nDGU6W8iO3ZkcLEqr-CBwvx0p2WAxzt8RiwQQ",
		"response": {
			"attestationObject": "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVjEdKbqkhPJnC90siSSsyDPQCYqlMGpUKA5fyklC2CEHvBBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQOia8u9zP1lVg6Fy7BsUbAVVR6T1g6TctRExl1BLyS3UwJ-RMOpwxlOlvIjt2ZHCxKq_ggcL8dKdlgMc7fEYsEGlAQIDJiABIVgg--n_QvZithDycYmnifk6vMHiwBP6kugn2PlsnvkrcSgiWCBAlBYm2B-rMtQlp5MxGTLoGDHoktxb0p364Hy2BH9U2Q",
			"clientDataJSON": "eyJjaGFsbGVuZ2UiOiJzVnQ0U2NjZU16cUZTbmZBcThoZ0x6Ymx2bzNmYTRfYUZWRWNJRVNISUowIiwib3JpZ2luIjoiaHR0cHM6Ly93ZWJhdXRobi5pbyIsInR5cGUiOiJ3ZWJhdXRobi5jcmVhdGUifQ"
		},
		"type": "public-key"
	}`,
	// TPM Attestation from Windows Hello Hardware AAGUID
	`{
        "id": "BoLAd0jIDI0ztrH1N45XQ_0w_N5ndt3hpNixQi3J2No",
        "rawId": "BoLAd0jIDI0ztrH1N45XQ_0w_N5ndt3hpNixQi3J2No",
        "response": {
          "attestationObject": "o2NmbXRjdHBtZ2F0dFN0bXSmY2FsZzn__mNzaWdZAQAzaz3HmrpCUlkEV2iv-TF2_y0MD7MVc0rLyuD_Ah3X9vx3G21WgeI89PyyvEYw3yEUUdO7sn6YxubMfuePpuSawYKAeSbw3O4LkMDC2fqZmlLyTfoC8L1_8vExv6mWPN7H5U6E_K7IZ38H3mO736ie-mDyoXxalj4WkA9zjKXJM5t7GhHQAqtDaX4HmM47pFH25atgQnoLdB0MTzh6jgYjIiDrMSOqhrQYskiaX_LFfKTiWfviwMOYcMA8FkRPc05LKvPTxp-bx_ghHrd_gIAUA3MjfElVYCVfveMnI61ZwARnf0cTrFp7vfga85YeAXaLOu29JifjodW6DsjL_dnXY3ZlcmMyLjBjeDVjglkFtTCCBbEwggOZoAMCAQICEAaSyUKea0mgpfZbwvZ7byMwDQYJKoZIhvcNAQELBQAwQTE_MD0GA1UEAxM2RVVTLU5UQy1LRVlJRC0yM0Y0RTIyQUQzQkUzNzRBNDQ5NzcyOTU0QUEyODNBRUQ3NTI1NzJFMB4XDTIxMTEyNTIxMzA1NFoXDTI3MDYwMzE3NTE0N1owADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANwiGFmQdIOYto4qGegANWT-LdSr5T5_tj7E_aKtLSNP8bqc6eP11VvCi9ZFnbjiFxi1NdY2GAbUDb3zr1PnZpOcwvn1gh704PLtkZYFkwvFRvm5bIvtsuqYgn71MCup1GCTeJ3EcylidbVpmwX5s9XK5vyRsMpQ1TxPwxPq32toIBcQ3pgZyb9Ic_m1IfWE_hC_XlwZzqfFnFL7XszCGwJmziFjML9VeBrdv0dkrDWMv1sNI1PDDm_JQ8iZwZ83At3qsgnmwN4zudOMUPRMJBNeiVBj9GjW7tV9tSG2Oa_F_JUo0b1Gr_y08PSMhAckj6ZaR8_EBppoty9CbTm65nsCAwEAAaOCAeQwggHgMA4GA1UdDwEB_wQEAwIHgDAMBgNVHRMBAf8EAjAAMG0GA1UdIAEB_wRjMGEwXwYJKwYBBAGCNxUfMFIwUAYIKwYBBQUHAgIwRB5CAFQAQwBQAEEAIAAgAFQAcgB1AHMAdABlAGQAIAAgAFAAbABhAHQAZgBvAHIAbQAgACAASQBkAGUAbgB0AGkAdAB5MBAGA1UdJQQJMAcGBWeBBQgDMEoGA1UdEQEB_wRAMD6kPDA6MTgwDgYFZ4EFAgMMBWlkOjcyMBAGBWeBBQICDAdOUENUNzV4MBQGBWeBBQIBDAtpZDo0RTU0NDMwMDAfBgNVHSMEGDAWgBTTjd-fy_wwa14b1TQrBpJk2U7fpTAdBgNVHQ4EFgQUeq9wlX_04m4THgx-yMSO7QwViv8wgbIGCCsGAQUFBwEBBIGlMIGiMIGfBggrBgEFBQcwAoaBkmh0dHA6Ly9hemNzcHJvZGV1c2Fpa3B1Ymxpc2guYmxvYi5jb3JlLndpbmRvd3MubmV0L2V1cy1udGMta2V5aWQtMjNmNGUyMmFkM2JlMzc0YTQ0OTc3Mjk1NGFhMjgzYWVkNzUyNTcyZS8xMzY0YTJkMy1hZTU0LTQ3YjktODdmMy0zMjA1NDE5NDc0MGUuY2VyMA0GCSqGSIb3DQEBCwUAA4ICAQCiPgQwqysYPQpMiRDpxbsx24d1xVX_kiUwwcQJE3mSYvwe4tnaQSHjlfB3OkpDMjotxFl33oUMxxScjSrgp_1o6rdkiO6QvPMgsqDMX4w-dmWn00akwNbMasTxg39Ceqtocw4i-R9AlNwndpe3QUIt8xkQ5dhlcIF8lc1dXmgz4mkMAtOi3VgaNvHTsRF9pLbTczJss608X8b4gHqM4t7lfIcRB8DvSyfXc7T3k21-4_3jvAb2HRoCCAyv8_XXn1UwkWTrXMLUSiE1p5Sl8ba8I_86Hsemsc0aflwRZrrY2pC3aaA3QbbfAyskiaFPw-ZibY9p0_QVq1XhAKa-dDd70mWvTGKQdrqfZI_SC5zccvDAm6aefAfnYBY2fV92ZFriihA2ULcJaESz3X3JkiK4eO1k0T2uf9-rL4lUEADibwpnsZOBeNWBsztvXDmcZGR_MSoRIQygKMw2U7AproqBPDRDFwhS5yc9UHvD6dMZ3PLx4i_eo-BLr-QJ2HARoyK8KuV0xLEq3XyjWdfZDbAueUVgtic14wK9jiSbhycRT2WV3-QU8KPm5_QCt_eBPwY81a-q84jm2ue_ok8-LYrmWpvihqRhFhK9MLVS96QaHeeuDehYNDWsSIVCr9jB-lchueZ-kZqwyl_4pPMrM7wLXBOR-bV5_pAPv3u_RvQmhVkG7zCCBuswggTToAMCAQICEzMAAAQHrjuoB9SvW8wAAAAABAcwDQYJKoZIhvcNAQELBQAwgYwxCzAJBgNVBAYTAlVTMRMwEQYDVQQIEwpXYXNoaW5ndG9uMRAwDgYDVQQHEwdSZWRtb25kMR4wHAYDVQQKExVNaWNyb3NvZnQgQ29ycG9yYXRpb24xNjA0BgNVBAMTLU1pY3Jvc29mdCBUUE0gUm9vdCBDZXJ0aWZpY2F0ZSBBdXRob3JpdHkgMjAxNDAeFw0yMTA2MDMxNzUxNDdaFw0yNzA2MDMxNzUxNDdaMEExPzA9BgNVBAMTNkVVUy1OVEMtS0VZSUQtMjNGNEUyMkFEM0JFMzc0QTQ0OTc3Mjk1NEFBMjgzQUVENzUyNTcyRTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoCggIBAMkPU9X8JhPBwDxmFm84D31b8xN5NQz0XR8Nji_-Z8v3WtC4lSdEwJUwqvZkj5OQ3wPA_6haONcCHzqTZhyz1aheOPhXmEeWFWjEiJFj07crEZb9wM4rM1fdcf3vCQNSSDlogC5AM-tITx31hm0YffIrzM3n70fNBBfvlw8t-yhZVOavj7l29gKsyvkR0IadruvLVWWVeH9rueHVrOwlU4wUJpjD41d4U87M3FgUGK2YacQxT0BPHzaOCTE9YhylG5fA_eCF7Q1SxAe347uIaS6I3GhAootzJy9XYeFp_uhc1Yp2hMh5wdeRkm15WKb7tE9T4vwHp0VCQEkUQn1ClN_s7PpfKNFp-DB9ez0Fh7tqag6AssrKE6LgOjfWDWUcgzgIiFLvv9Gx797IZj8LDazK1iGSqI2D8zmmxnGG47MevfY8q2udJW1G4nOcjw49x6XZHmnT3VpVKcTDbI9bEsyc2R9vngftF9FgnEVdyt-QRqE0UqEXJmjLhcxBMeyFZJd_bEAutSBpWugPk10IPFRkXppsuHMZFHJVP96IWwVmm6Q4mX018K996XDubAGblbhvPzJ9NFL_e7xM2ev3rAalz2CzSLYs48EXym7dqGTnP7F9DaF2O0IHT0GQ951wFVoGmA-IYsTMVsdlhVaImCuHgahu1W94H6BvtDkGGku7AgMBAAGjggGOMIIBijAOBgNVHQ8BAf8EBAMCAoQwGwYDVR0lBBQwEgYJKwYBBAGCNxUkBgVngQUIAzAWBgNVHSAEDzANMAsGCSsGAQQBgjcVHzASBgNVHRMBAf8ECDAGAQH_AgEAMB0GA1UdDgQWBBTTjd-fy_wwa14b1TQrBpJk2U7fpTAfBgNVHSMEGDAWgBR6jArOL0hiF-KU0a5VwVLscXSkVjBwBgNVHR8EaTBnMGWgY6Bhhl9odHRwOi8vd3d3Lm1pY3Jvc29mdC5jb20vcGtpb3BzL2NybC9NaWNyb3NvZnQlMjBUUE0lMjBSb290JTIwQ2VydGlmaWNhdGUlMjBBdXRob3JpdHklMjAyMDE0LmNybDB9BggrBgEFBQcBAQRxMG8wbQYIKwYBBQUHMAKGYWh0dHA6Ly93d3cubWljcm9zb2Z0LmNvbS9wa2lvcHMvY2VydHMvTWljcm9zb2Z0JTIwVFBNJTIwUm9vdCUyMENlcnRpZmljYXRlJTIwQXV0aG9yaXR5JTIwMjAxNC5jcnQwDQYJKoZIhvcNAQELBQADggIBAIQJqhFB71eZzZMq0w866QXDKlHcGyIa_IkTK4p5ejIdIA7FJ8neeVToAKUt9ULEb1Od2ir1y5Qx5Zp_edf4F8aikn-yw61hNB3FQ4iSV49eqEMe2Fx6OMBmHRWGtUjAlf5g_N2Qc6rHela2d69nQbpSF3Nq7AESguXxnoqZ-4CGUW0jC_b93sTd5fESHs_iwFX-zWKCwCXerqCuI3PqYWOlbCnftYhsI1CD638wJxw4YFXdSmOrF8dDnd6tlH_0qCZrBX-k4N-8QgK1-BDYIxmvUBnpLFDDitB2dP6YIglY0VcjkPd3BDmodHknG4GQeAvJKHpqF91Y3K1rOWvn4JqzHFvL3JgXgL7LbC_h9EF50HeHayPCToTS8Pmg_4dfUaCwNlxPvu9GvjrDKDNNEV5T73iWMV_GQbVsx6JULAljCthYLo-55mONDcr1x7kakXlQT-yIdIQ57Ix8eHz_qkJkvWxbw8vOgrXhkLK0jGAvW_YSkTV7G9_TYDJ--8IjPPHC1bexKq72-L7KetwH6LbWHGeYkJnaZ1zqeN4USxyJn8K4uhwnjSeK2sZ942zn5EnZnjd85yfdkPLcQY8xtYiWNjc_PprTrjhLyMO71VdMkTDiTTtDha37qywNISPV7vBv8YDiDjX8ElsWbTHTC0XgBp0h-RkjaRKI5C4eTUebZ3B1YkFyZWFYdgAjAAsABAByACCd_8vzbDg65pn7mGjcbcuJ1xU4hL4oA5IsEkFYv60irgAQABAAAwAQACCweOEk52r8mnJ6y9bsGcM3V4dL1LWt8I67Jjx5mcrFuAAgjwd_jaCEEOAJLV97kX3VgbxzopPYMC4NqEFjD0m55PpoY2VydEluZm9Yof9UQ0eAFwAiAAvgBLotxyAAbygBG4efe84V0SVYnO6xLrYaC1oyLgTt3QAUjcjAdORvuzxCfLBU7KNxPFSPE84AAAAUHn9jxccO2yRJARoXARNN0IPNWxnEACIACxfcHNQuRgb_05OKyBrS_1kY5IYxOl67gTlqkHd4g6slACIAC7tcXSHNTw8ANLeZd3PKooKsgrMIlGD47aunn05BcquwaGF1dGhEYXRhWKRqubvw35oW-R27M7uxMvr50Xx4LEgmxuxw7O5Y2X71KkUAAAAACJhwWMrcS4G24TDeUNy-lgAgBoLAd0jIDI0ztrH1N45XQ_0w_N5ndt3hpNixQi3J2NqlAQIDJiABIVggsHjhJOdq_JpyesvW7BnDN1eHS9S1rfCOuyY8eZnKxbgiWCCPB3-NoIQQ4AktX3uRfdWBvHOik9gwLg2oQWMPSbnk-g",
          "clientDataJSON": "eyJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIiwiY2hhbGxlbmdlIjoiRTJZZWJNbUc5OTkyWGlhbHBGTDFsa1BwdE9JQlBlS3NwaE5rdDFKY2JLayIsIm9yaWdpbiI6Imh0dHBzOi8vd2ViYXV0aG4uZmlyc3R5ZWFyLmlkLmF1IiwiY3Jvc3NPcmlnaW4iOmZhbHNlLCJvdGhlcl9rZXlzX2Nhbl9iZV9hZGRlZF9oZXJlIjoiZG8gbm90IGNvbXBhcmUgY2xpZW50RGF0YUpTT04gYWdhaW5zdCBhIHRlbXBsYXRlLiBTZWUgaHR0cHM6Ly9nb28uZ2wveWFiUGV4In0"
        },
        "type": "public-key",
        "extensions": {
          "appid": null,
          "cred_blob": null,
          "cred_props": { "rk": true }
        }
	}`,
}
