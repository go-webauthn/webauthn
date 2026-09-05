//go:build go1.27

package protocol

import (
	"crypto/mldsa"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"slices"
	"testing"
	"time"

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

// TestAKPHelpersRejectOtherKeyTypes asserts that neither helper claims a key which is not of the AKP key type. Each
// is reached only from the default arm of a switch which has already handled every other key type, so a helper
// which claimed one of them would divert a key away from the branch that knows how to handle it.
func TestAKPHelpersRejectOtherKeyTypes(t *testing.T) {
	keys := []any{
		struct{}{},
		webauthncose.EC2PublicKeyData{},
		webauthncose.RSAPublicKeyData{},
		webauthncose.OKPPublicKeyData{},
	}

	for _, key := range keys {
		algorithm, ok := akpKeyAlgorithm(key)

		assert.False(t, ok)
		assert.Zero(t, algorithm)

		public, ok, err := akpPublicKey(key)

		assert.False(t, ok)
		assert.Nil(t, public)
		require.NoError(t, err)
	}

	t.Run("ShouldClaimAKPKey", func(t *testing.T) {
		_, pub := mldsaTestCredentialPublicKey(t, webauthncose.AlgMLDSA44, mldsa.MLDSA44())

		parsed, err := webauthncose.ParsePublicKey(pub)

		require.NoError(t, err)

		algorithm, ok := akpKeyAlgorithm(parsed)

		assert.True(t, ok)
		assert.Equal(t, int64(webauthncose.AlgMLDSA44), algorithm)

		public, ok, err := akpPublicKey(parsed)

		assert.True(t, ok)
		require.NoError(t, err)
		assert.NotNil(t, public)
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

// TestPackedFormat_BasicAttestationMLDSA asserts that a packed full attestation whose x5c is an ML-DSA chain
// verifies, and that the parameter set the certificate holds is bound to the algorithm the statement declares.
//
// The chain is verified as well as the statement, as an ML-DSA attestation certificate is only usable as a trust
// path if the certificates it is issued under can be built into one. The leaf and the root name different parameter
// sets so that neither the signature check nor the chain check can pass by treating ML-DSA as a single algorithm.
//
// Specification: §8.2. Packed Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-packed-attestation)
func TestPackedFormat_BasicAttestationMLDSA(t *testing.T) {
	rootKey, err := mldsa.GenerateKey(mldsa.MLDSA65())

	require.NoError(t, err)

	leafKey, err := mldsa.GenerateKey(mldsa.MLDSA44())

	require.NoError(t, err)

	root := mldsaTestCertificate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "ML-DSA Attestation Root"},
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign,
	}, nil, rootKey.PublicKey(), rootKey)

	leaf := mldsaTestCertificate(t, &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Country:            []string{"US"},
			Organization:       []string{"Test Vendor"},
			OrganizationalUnit: []string{"Authenticator Attestation"},
			CommonName:         "ML-DSA Attestation Leaf",
		},
	}, root, leafKey.PublicKey(), rootKey)

	roots := x509.NewCertPool()

	roots.AddCert(root)

	_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny}})

	require.NoError(t, err)

	authData, clientDataHash := []byte("authenticator data"), []byte("client data hash")

	sig, err := leafKey.Sign(nil, slices.Concat(authData, clientDataHash), &mldsa.Options{})

	require.NoError(t, err)

	x5c := []any{leaf.Raw, root.Raw}
	aaguid := make([]byte, 16)

	attestationType, path, err := handleBasicAttestation(sig, clientDataHash, authData, aaguid, int64(webauthncose.AlgMLDSA44), x5c, nil, SignaturePolicy{})

	require.NoError(t, err)
	assert.Equal(t, string(metadata.BasicFull), attestationType)
	assert.Equal(t, x5c, path)

	t.Run("ShouldRejectAlgorithmNamingAnotherParameterSet", func(t *testing.T) {
		_, _, err := handleBasicAttestation(sig, clientDataHash, authData, aaguid, int64(webauthncose.AlgMLDSA87), x5c, nil, SignaturePolicy{})

		require.ErrorContains(t, err, "but have a public key with ML-DSA-44 parameters")
	})

	t.Run("ShouldRejectAlgorithmNamingAnotherKeyType", func(t *testing.T) {
		_, _, err := handleBasicAttestation(sig, clientDataHash, authData, aaguid, int64(webauthncose.AlgES256), x5c, nil, SignaturePolicy{})

		require.ErrorContains(t, err, "signature algorithm specifies an ECDSA public key")
	})

	t.Run("ShouldRejectSignatureOverDifferentData", func(t *testing.T) {
		_, _, err := handleBasicAttestation(sig, clientDataHash, []byte("different data"), aaguid, int64(webauthncose.AlgMLDSA44), x5c, nil, SignaturePolicy{})

		require.ErrorContains(t, err, "ML-DSA verification failure")
	})
}

func mldsaTestCertificate(t *testing.T, template, parent *x509.Certificate, pub, signer any) *x509.Certificate {
	t.Helper()

	template.NotBefore, template.NotAfter = time.Now().Add(-time.Hour), time.Now().Add(time.Hour)

	if parent == nil {
		parent = template
	}

	der, err := x509.CreateCertificate(rand.Reader, template, parent, pub, signer)

	require.NoError(t, err)

	cert, err := x509.ParseCertificate(der)

	require.NoError(t, err)

	return cert
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
