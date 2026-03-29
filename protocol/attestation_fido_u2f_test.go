package protocol

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
)

func TestVerifyU2FFormat(t *testing.T) {
	successAttResponse := attestationTestUnpackResponse(t, u2fTestResponse["success"]).Response.AttestationObject
	successClientDataHash := sha256.Sum256(attestationTestUnpackResponse(t, u2fTestResponse["success"]).Raw.AttestationResponse.ClientDataJSON)

	testCases := []struct {
		name            string
		att             AttestationObject
		clientDataHash  []byte
		attestationType string
		err             string
	}{
		{
			name:            "ShouldSuccessfullyVerifyU2FFormat",
			att:             successAttResponse,
			clientDataHash:  successClientDataHash[:],
			attestationType: string(metadata.BasicFull),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			attestationType, _, err := attestationFormatValidationHandlerFIDOU2F(tc.att, tc.clientDataHash, nil)

			if tc.err != "" {
				require.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)
			}

			assert.Equal(t, tc.attestationType, attestationType)
		})
	}
}

func TestVerifyU2FFormat_Errors(t *testing.T) {
	zeroAAGUID := make([]byte, 16)

	es256Key := []byte{
		0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01,
		0x21, 0x58, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x22, 0x58, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	testCases := []struct {
		name string
		att  AttestationObject
		err  string
	}{
		{
			name: "ShouldFailNonZeroAAGUID",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID: []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16},
					},
				},
			},
			err: "U2F attestation format AAGUID not set to 0x00",
		},
		{
			name: "ShouldFailInvalidPublicKey",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: []byte("not-cbor"),
					},
				},
			},
			err: "Error parsing public key",
		},
		{
			name: "ShouldFailNonES256Algorithm",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID: zeroAAGUID,
						CredentialPublicKey: []byte{
							0xa3, 0x01, 0x02, 0x03, 0x39, 0x01, 0x00, 0x20, 0x01,
						},
					},
				},
			},
			err: "Non-ES256 Public Key algorithm used",
		},
		{
			name: "ShouldFailMissingX5C",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: es256Key,
					},
				},
				AttStatement: map[string]any{},
			},
			err: "Missing properly formatted x5c data",
		},
		{
			name: "ShouldFailMissingSig",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: es256Key,
					},
				},
				AttStatement: map[string]any{
					stmtX5C: []any{[]byte("cert")},
				},
			},
			err: "Missing sig data",
		},
		{
			name: "ShouldFailX5CNotExactlyOne",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: es256Key,
					},
				},
				AttStatement: map[string]any{
					stmtX5C:       []any{[]byte("cert1"), []byte("cert2")},
					stmtSignature: []byte("sig"),
				},
			},
			err: "x5c must contain exactly one element",
		},
		{
			name: "ShouldFailX5CElementNotBytes",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: es256Key,
					},
				},
				AttStatement: map[string]any{
					stmtX5C:       []any{"not-bytes"},
					stmtSignature: []byte("sig"),
				},
			},
			err: "Error decoding ASN.1 data from x5c",
		},
		{
			name: "ShouldFailX5CInvalidCert",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: es256Key,
					},
				},
				AttStatement: map[string]any{
					stmtX5C:       []any{[]byte("not-a-cert")},
					stmtSignature: []byte("sig"),
				},
			},
			err: "Error parsing certificate from ASN.1 data into certificate",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := attestationFormatValidationHandlerFIDOU2F(tc.att, []byte("hash"), nil)
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestVerifyU2FFormat_CertificateErrors(t *testing.T) {
	zeroAAGUID := make([]byte, 16)

	es256Key := []byte{
		0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01,
		0x21, 0x58, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x22, 0x58, 0x20,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	shortCoordKey := []byte{
		0xa5, 0x01, 0x02, 0x03, 0x26, 0x20, 0x01,
		0x21, 0x58, 0x10,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
		0x22, 0x58, 0x10,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01,
	}

	rsaCertDER := u2fTestGenerateRSACert(t)
	p384CertDER := u2fTestGenerateP384Cert(t)
	p256CertDER := u2fTestGenerateP256Cert(t)

	testCases := []struct {
		name string
		att  AttestationObject
		err  string
	}{
		{
			name: "ShouldFailNonECDSACert",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: es256Key,
					},
				},
				AttStatement: map[string]any{
					stmtX5C:       []any{rsaCertDER},
					stmtSignature: []byte("sig"),
				},
			},
			err: "Attestation certificate public key algorithm is not ECDSA",
		},
		{
			name: "ShouldFailNonP256Curve",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: es256Key,
					},
				},
				AttStatement: map[string]any{
					stmtX5C:       []any{p384CertDER},
					stmtSignature: []byte("sig"),
				},
			},
			err: "Attestation certificate does not contain a P-256 ECDSA public key",
		},
		{
			name: "ShouldFailShortCoordinates",
			att: AttestationObject{
				AuthData: AuthenticatorData{
					AttData: AttestedCredentialData{
						AAGUID:              zeroAAGUID,
						CredentialPublicKey: shortCoordKey,
					},
				},
				AttStatement: map[string]any{
					stmtX5C:       []any{p256CertDER},
					stmtSignature: []byte("sig"),
				},
			},
			err: "X or Y Coordinate for key is invalid length",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, _, err := attestationFormatValidationHandlerFIDOU2F(tc.att, []byte("hash"), nil)
			require.EqualError(t, err, tc.err)
		})
	}
}

// Supporting functions.

func u2fTestGenerateRSACert(t *testing.T) []byte {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test RSA"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return der
}

func u2fTestGenerateP384Cert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test P384"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return der
}

func u2fTestGenerateP256Cert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "Test P256"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)

	return der
}

var u2fTestResponse = map[string]string{
	`success`: `{
		"rawId": "7nJsttr4dLSsmrWnaHB3espJ0ua9rsJ2ws-93BFcNOP64g_s_4wLFDvklrNYcg0BCN6ddUjJLxDfDSBreKQLAw",
		"id": "7nJsttr4dLSsmrWnaHB3espJ0ua9rsJ2ws-93BFcNOP64g_s_4wLFDvklrNYcg0BCN6ddUjJLxDfDSBreKQLAw",
		"response": {
		  "clientDataJSON": "eyJjaGFsbGVuZ2UiOiJhTDJ1d0FwZ3d1bUJ6VFlDY29MMF80RFJ2X21mWXlremdxSkJGb0pqX1dDS05aT3B2VVFueWpkd01XSVdLY1k4NDR0eUROTE81cFFQQk1KckhQel8zZyIsImNsaWVudEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0OjQ0MzI5IiwidHlwZSI6IndlYmF1dGhuLmNyZWF0ZSJ9",
		  "attestationObject": "o2NmbXRoZmlkby11MmZnYXR0U3RtdKJjc2lnWEcwRQIgRMxowC__Z-mgVR6netL6C7Q15weqiTCPwwq1EaeJVqMCIQCHb9cCad1VloGhQ60mw7KTJhkx61mfgKKwHUVZf1wR6mN4NWOBWQLCMIICvjCCAaagAwIBAgIEdIb9wjANBgkqhkiG9w0BAQsFADAuMSwwKgYDVQQDEyNZdWJpY28gVTJGIFJvb3QgQ0EgU2VyaWFsIDQ1NzIwMDYzMTAgFw0xNDA4MDEwMDAwMDBaGA8yMDUwMDkwNDAwMDAwMFowbzELMAkGA1UEBhMCU0UxEjAQBgNVBAoMCVl1YmljbyBBQjEiMCAGA1UECwwZQXV0aGVudGljYXRvciBBdHRlc3RhdGlvbjEoMCYGA1UEAwwfWXViaWNvIFUyRiBFRSBTZXJpYWwgMTk1NTAwMzg0MjBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABJVd8633JH0xde_9nMTzGk6HjrrhgQlWYVD7OIsuX2Unv1dAmqWBpQ0KxS8YRFwKE1SKE1PIpOWacE5SO8BN6-2jbDBqMCIGCSsGAQQBgsQKAgQVMS4zLjYuMS40LjEuNDE0ODIuMS4xMBMGCysGAQQBguUcAgEBBAQDAgUgMCEGCysGAQQBguUcAQEEBBIEEPigEfOMCk0VgAYXER-e3H0wDAYDVR0TAQH_BAIwADANBgkqhkiG9w0BAQsFAAOCAQEAMVxIgOaaUn44Zom9af0KqG9J655OhUVBVW-q0As6AIod3AH5bHb2aDYakeIyyBCnnGMHTJtuekbrHbXYXERIn4aKdkPSKlyGLsA_A-WEi-OAfXrNVfjhrh7iE6xzq0sg4_vVJoywe4eAJx0fS-Dl3axzTTpYl71Nc7p_NX6iCMmdik0pAuYJegBcTckE3AoYEg4K99AM_JaaKIblsbFh8-3LxnemeNf7UwOczaGGvjS6UzGVI0Odf9lKcPIwYhuTxM5CaNMXTZQ7xq4_yTfC3kPWtE4hFT34UJJflZBiLrxG4OsYxkHw_n5vKgmpspB3GfYuYTWhkDKiE8CYtyg87mhhdXRoRGF0YVjESZYN5YgOjGh0NBcPZHZgW4_krrmihjLHmVzzuoMdl2NBAAAAAAAAAAAAAAAAAAAAAAAAAAAAQO5ybLba-HS0rJq1p2hwd3rKSdLmva7CdsLPvdwRXDTj-uIP7P-MCxQ75JazWHINAQjenXVIyS8Q3w0ga3ikCwOlAQIDJiABIVggUOAo5xqsJoPfJWsU50h7c2S7_llP0KwGI6vJkEj1N48iWCA2TMSeBfhJ84HyMQQgjJvBiA6JnHA0chxSlmuZeT9Xgg"
		},
		"type": "public-key"
	  }`,
}
