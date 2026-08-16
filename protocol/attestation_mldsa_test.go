//go:build go1.27

package protocol

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestVerifyAttestationPublicKeyMatchMLDSA(t *testing.T) {
	private, pub := mldsaTestCredentialPublicKey(t, webauthncose.AlgMLDSA44, mldsa.MLDSA44())

	att := AttestationObject{
		AuthData: AuthenticatorData{
			AttData: AttestedCredentialData{
				CredentialPublicKey: pub,
			},
		},
	}

	certificate := func(t *testing.T, key *mldsa.PrivateKey) *x509.Certificate {
		t.Helper()

		template := &x509.Certificate{SerialNumber: big.NewInt(1)}

		der, err := x509.CreateCertificate(rand.Reader, template, template, key.PublicKey(), key)

		require.NoError(t, err)

		cert, err := x509.ParseCertificate(der)

		require.NoError(t, err)

		return cert
	}

	credentialPublicKey, err := verifyAttestationPublicKeyMatch(att, certificate(t, private))

	require.NoError(t, err)
	assert.IsType(t, webauthncose.AKPPublicKeyData{}, credentialPublicKey)

	t.Run("ShouldRejectCertificateHoldingAnotherKey", func(t *testing.T) {
		other, err := mldsa.GenerateKey(mldsa.MLDSA44())

		require.NoError(t, err)

		_, err = verifyAttestationPublicKeyMatch(att, certificate(t, other))

		require.EqualError(t, err, "Certificate public key does not match public key in authData")
	})
}

// TestPackedFormat_SelfAttestationMLDSA asserts that a packed self attestation made with an ML-DSA credential key
// verifies, and that a statement whose alg contradicts the credential public key does not.
//
// Specification: §8.2. Packed Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation)
func TestPackedFormat_SelfAttestationMLDSA(t *testing.T) {
	testCases := []struct {
		alg    webauthncose.COSEAlgorithmIdentifier
		params mldsa.Parameters
	}{
		{webauthncose.AlgMLDSA44, mldsa.MLDSA44()},
		{webauthncose.AlgMLDSA65, mldsa.MLDSA65()},
		{webauthncose.AlgMLDSA87, mldsa.MLDSA87()},
	}

	for _, tc := range testCases {
		t.Run(tc.alg.String(), func(t *testing.T) {
			private, err := mldsa.GenerateKey(tc.params)

			require.NoError(t, err)

			pub, err := webauthncbor.Marshal(struct {
				_struct   bool   `cbor:",keyasint"` //nolint:govet,staticcheck,unused
				KeyType   int64  `cbor:"1,keyasint"`
				Algorithm int64  `cbor:"3,keyasint"`
				PublicKey []byte `cbor:"-1,keyasint"`
			}{
				KeyType:   int64(webauthncose.AKP),
				Algorithm: int64(tc.alg),
				PublicKey: private.PublicKey().Bytes(),
			})

			require.NoError(t, err)

			authData, clientDataHash := []byte("authenticator data"), []byte("client data hash")

			sig, err := private.Sign(nil, append(append([]byte{}, authData...), clientDataHash...), &mldsa.Options{})

			require.NoError(t, err)

			attestationType, x5c, err := handleSelfAttestation(int64(tc.alg), pub, authData, clientDataHash, sig, nil, SignaturePolicy{})

			require.NoError(t, err)
			assert.Nil(t, x5c)
			assert.Equal(t, string(metadata.BasicSurrogate), attestationType)

			t.Run("ShouldRejectAlgorithmWhichDoesNotMatchTheCredentialKey", func(t *testing.T) {
				_, _, err := handleSelfAttestation(int64(webauthncose.AlgES256), pub, authData, clientDataHash, sig, nil, SignaturePolicy{})

				require.EqualError(t, err, "Public key algorithm does not equal att statement algorithm")
			})

			t.Run("ShouldRejectSignatureOverDifferentData", func(t *testing.T) {
				_, _, err := handleSelfAttestation(int64(tc.alg), pub, []byte("different data"), clientDataHash, sig, nil, SignaturePolicy{})

				require.EqualError(t, err, "Unable to verify signature")
			})
		})
	}
}

func mldsaTestCredentialPublicKey(t *testing.T, alg webauthncose.COSEAlgorithmIdentifier, params mldsa.Parameters) (*mldsa.PrivateKey, []byte) {
	t.Helper()

	private, err := mldsa.GenerateKey(params)

	require.NoError(t, err)

	pub, err := webauthncbor.Marshal(struct {
		_struct   bool   `cbor:",keyasint"` //nolint:govet,staticcheck,unused
		KeyType   int64  `cbor:"1,keyasint"`
		Algorithm int64  `cbor:"3,keyasint"`
		PublicKey []byte `cbor:"-1,keyasint"`
	}{
		KeyType:   int64(webauthncose.AKP),
		Algorithm: int64(alg),
		PublicKey: private.PublicKey().Bytes(),
	})

	require.NoError(t, err)

	return private, pub
}
