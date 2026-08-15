package webauthn

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/x/crypto/secp256k1"
	secp256k1ecdsa "github.com/go-webauthn/x/crypto/secp256k1/ecdsa"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

const (
	testES256KRPID   = "example.org"
	testES256KOrigin = "https://example.org"
)

func TestES256KCeremoniesEndToEnd(t *testing.T) {
	private, err := secp256k1.GeneratePrivateKey()

	require.NoError(t, err)

	w := &WebAuthn{Config: &Config{RPID: testES256KRPID, RPOrigins: []string{testES256KOrigin}}}

	userID := []byte(testUserID)
	credentialID := []byte("es256k-credential-identifier-000")

	challenge := base64.RawURLEncoding.EncodeToString([]byte("es256k registration challenge 00"))

	attestedData := testES256KAttestedCredentialData(t, credentialID, testES256KCredentialPublicKey(t, private))
	authData := testES256KAuthenticatorData(t, protocol.FlagUserPresent|protocol.FlagAttestedCredentialData, 0, attestedData)
	clientDataJSON := testES256KClientDataJSON(t, "webauthn.create", challenge)

	body := testES256KRegistrationBody(t, credentialID, testES256KAttestationObject(t, authData, testES256KSign(t, private, authData, clientDataJSON)), clientDataJSON)

	parsedRegistration, err := protocol.ParseCredentialCreationResponseBytes(body)

	require.NoError(t, err)

	session := SessionData{
		UserID:     userID,
		Challenge:  challenge,
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256K}},
	}

	user := &defaultUser{id: userID}

	credential, err := w.CreateCredential(user, session, parsedRegistration)

	require.NoError(t, err)
	require.NotNil(t, credential)

	assert.Equal(t, credentialID, credential.ID)
	assert.Equal(t, "basic_surrogate", credential.AttestationType)
	assert.Equal(t, "packed", credential.AttestationFormat)

	t.Run("ShouldRejectRegistrationWhenAlgorithmNotRequested", func(t *testing.T) {
		unrequested := session
		unrequested.CredParams = CredentialParametersRecommendedL3()

		credential, err := w.CreateCredential(user, unrequested, parsedRegistration)

		assert.Nil(t, credential)
		assert.EqualError(t, err, "Invalid attestation format")
	})

	t.Run("ShouldValidateAssertion", func(t *testing.T) {
		challenge := base64.RawURLEncoding.EncodeToString([]byte("es256k assertion challenge 00000"))

		authData := testES256KAuthenticatorData(t, protocol.FlagUserPresent, 1, nil)
		clientDataJSON := testES256KClientDataJSON(t, "webauthn.get", challenge)

		parsedAssertion, err := protocol.ParseCredentialRequestResponseBytes(testES256KAssertionBody(t, credentialID, authData, clientDataJSON, testES256KSign(t, private, authData, clientDataJSON)))

		require.NoError(t, err)

		user := &defaultUser{id: userID, credentials: []Credential{*credential}}

		validated, err := w.ValidateLogin(user, SessionData{UserID: userID, Challenge: challenge}, parsedAssertion)

		require.NoError(t, err)
		require.NotNil(t, validated)

		assert.Equal(t, credentialID, validated.ID)
		assert.Equal(t, uint32(1), validated.Authenticator.SignCount)
	})

	t.Run("ShouldRejectAssertionSignedByAnotherKey", func(t *testing.T) {
		other, err := secp256k1.GeneratePrivateKey()

		require.NoError(t, err)

		challenge := base64.RawURLEncoding.EncodeToString([]byte("es256k assertion challenge 00001"))

		authData := testES256KAuthenticatorData(t, protocol.FlagUserPresent, 2, nil)
		clientDataJSON := testES256KClientDataJSON(t, "webauthn.get", challenge)

		parsedAssertion, err := protocol.ParseCredentialRequestResponseBytes(testES256KAssertionBody(t, credentialID, authData, clientDataJSON, testES256KSign(t, other, authData, clientDataJSON)))

		require.NoError(t, err)

		user := &defaultUser{id: userID, credentials: []Credential{*credential}}

		validated, err := w.ValidateLogin(user, SessionData{UserID: userID, Challenge: challenge}, parsedAssertion)

		assert.Nil(t, validated)
		assert.EqualError(t, err, "Error validating the assertion signature: <nil>")
	})
}

func TestES256KWithPackedBasicAttestation(t *testing.T) {
	credentialKey, err := secp256k1.GeneratePrivateKey()

	require.NoError(t, err)

	attestationKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	require.NoError(t, err)

	w := &WebAuthn{Config: &Config{RPID: testES256KRPID, RPOrigins: []string{testES256KOrigin}}}

	userID := []byte(testUserID)
	credentialID := []byte("es256k-credential-identifier-001")

	challenge := base64.RawURLEncoding.EncodeToString([]byte("es256k attestation challenge 000"))

	attestedData := testES256KAttestedCredentialData(t, credentialID, testES256KCredentialPublicKey(t, credentialKey))
	authData := testES256KAuthenticatorData(t, protocol.FlagUserPresent|protocol.FlagAttestedCredentialData, 0, attestedData)
	clientDataJSON := testES256KClientDataJSON(t, "webauthn.create", challenge)

	clientDataHash := sha256.Sum256(clientDataJSON)

	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)

	digest := sha256.Sum256(signed)

	sig, err := ecdsa.SignASN1(rand.Reader, attestationKey, digest[:])

	require.NoError(t, err)

	attestationObject, err := webauthncbor.Marshal(map[string]any{
		"fmt": "packed",
		"attStmt": map[string]any{
			"alg": int64(webauthncose.AlgES256),
			"sig": sig,
			"x5c": []any{testES256KAttestationCertificate(t, attestationKey)},
		},
		"authData": authData,
	})

	require.NoError(t, err)

	parsedRegistration, err := protocol.ParseCredentialCreationResponseBytes(testES256KRegistrationBody(t, credentialID, attestationObject, clientDataJSON))

	require.NoError(t, err)

	session := SessionData{
		UserID:     userID,
		Challenge:  challenge,
		CredParams: []protocol.CredentialParameter{{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256K}},
	}

	credential, err := w.CreateCredential(&defaultUser{id: userID}, session, parsedRegistration)

	require.NoError(t, err)
	require.NotNil(t, credential)

	assert.Equal(t, credentialID, credential.ID)
	assert.Equal(t, "basic_full", credential.AttestationType)
	assert.Equal(t, "packed", credential.AttestationFormat)
}

func testES256KAttestationCertificate(t *testing.T, key *ecdsa.PrivateKey) []byte {
	t.Helper()

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Test Vendor"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "Test Attestation",
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		BasicConstraintsValid: true,
	}

	data, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)

	require.NoError(t, err)

	return data
}

func testES256KCredentialPublicKey(t *testing.T, private *secp256k1.PrivateKey) []byte {
	t.Helper()

	public := private.PubKey()

	data, err := webauthncbor.Marshal(map[int64]any{
		1:  int64(webauthncose.EllipticKey),
		3:  int64(webauthncose.AlgES256K),
		-1: int64(webauthncose.Secp256k1),
		-2: public.X().FillBytes(make([]byte, 32)),
		-3: public.Y().FillBytes(make([]byte, 32)),
	})

	require.NoError(t, err)

	return data
}

func testES256KAttestedCredentialData(t *testing.T, credentialID, credentialPublicKey []byte) []byte {
	t.Helper()

	require.Less(t, len(credentialID), 1024)

	data := make([]byte, 16, 16+2+len(credentialID)+len(credentialPublicKey))
	data = binary.BigEndian.AppendUint16(data, uint16(len(credentialID))) //nolint:gosec // The length is bounds checked above.
	data = append(data, credentialID...)

	return append(data, credentialPublicKey...)
}

func testES256KAuthenticatorData(t *testing.T, flags protocol.AuthenticatorFlags, signCount uint32, attestedData []byte) []byte {
	t.Helper()

	hash := sha256.Sum256([]byte(testES256KRPID))

	data := make([]byte, 0, 37+len(attestedData))
	data = append(data, hash[:]...)
	data = append(data, byte(flags))
	data = binary.BigEndian.AppendUint32(data, signCount)

	return append(data, attestedData...)
}

func testES256KClientDataJSON(t *testing.T, ceremony, challenge string) []byte {
	t.Helper()

	data, err := json.Marshal(map[string]any{
		"type":        ceremony,
		"challenge":   challenge,
		"origin":      testES256KOrigin,
		"crossOrigin": false,
	})

	require.NoError(t, err)

	return data
}

func testES256KSign(t *testing.T, private *secp256k1.PrivateKey, authData, clientDataJSON []byte) []byte {
	t.Helper()

	clientDataHash := sha256.Sum256(clientDataJSON)

	signed := make([]byte, 0, len(authData)+len(clientDataHash))
	signed = append(signed, authData...)
	signed = append(signed, clientDataHash[:]...)

	digest := sha256.Sum256(signed)

	return secp256k1ecdsa.Sign(private, digest[:]).Serialize()
}

func testES256KAttestationObject(t *testing.T, authData, sig []byte) []byte {
	t.Helper()

	data, err := webauthncbor.Marshal(map[string]any{
		"fmt":      "packed",
		"attStmt":  map[string]any{"alg": int64(webauthncose.AlgES256K), "sig": sig},
		"authData": authData,
	})

	require.NoError(t, err)

	return data
}

func testES256KRegistrationBody(t *testing.T, credentialID, attestationObject, clientDataJSON []byte) []byte {
	t.Helper()

	id := base64.RawURLEncoding.EncodeToString(credentialID)

	data, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
		},
	})

	require.NoError(t, err)

	return data
}

func testES256KAssertionBody(t *testing.T, credentialID, authData, clientDataJSON, sig []byte) []byte {
	t.Helper()

	id := base64.RawURLEncoding.EncodeToString(credentialID)

	data, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authData),
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientDataJSON),
			"signature":         base64.RawURLEncoding.EncodeToString(sig),
		},
	})

	require.NoError(t, err)

	return data
}
