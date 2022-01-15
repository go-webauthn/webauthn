package webauthncose

import (
	"crypto/rand"
	"testing"

	"golang.org/x/crypto/ed25519"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// TestOKPSignatureVerification is a compatibility test to ensure that removing
// a previously used dependency doesn't introduce new issues.
//
// Since OKPs are used to represent Ed25519 keys, this test largely ensures
// that the underlying Ed25519 signature verification passes.
func TestOKPSignatureVerification(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("error creating ed25519 key: %v", err)
	}
	data := []byte("Sample data to sign")
	validSig := ed25519.Sign(priv, data)
	invalidSig := []byte("invalid")

	key := OKPPublicKeyData{
		XCoord: pub,
	}
	// Test that a valid signature passes
	ok, err := key.Verify(data, validSig)
	if err != nil {
		t.Fatalf("error verifying okp signature: %v", err)
	}
	if !ok {
		t.Fatalf("valid signature wasn't properly verified")
	}
	// And that an invalid signature fails
	ok, err = key.Verify(data, invalidSig)
	if err != nil {
		t.Fatalf("error verifying okp signature: %v", err)
	}
	if ok {
		t.Fatalf("invalid signature was incorrectly verified")
	}
}

func TestOKPDisplayPublicKey(t *testing.T) {
	// Sample public key generated from ed25519.GenerateKey(rand.Reader)
	var pub ed25519.PublicKey = []byte{0x7b, 0x88, 0x10, 0x24, 0xad, 0xc9, 0x82, 0xd3, 0x80, 0xb8, 0x77, 0x1e, 0x3b, 0x9b, 0xf8, 0xe4, 0xb3, 0x99, 0x8b, 0xc7, 0xd0, 0x58, 0x30, 0x66, 0x2, 0xce, 0x4d, 0xf, 0x2f, 0xe4, 0xb7, 0x81}
	// The PEM encoded representation of the public key in PKIX, ASN.1 DER format.
	expected := `-----BEGIN PUBLIC KEY-----
MCowBQYDK2VwAyEAe4gQJK3JgtOAuHceO5v45LOZi8fQWDBmAs5NDy/kt4E=
-----END PUBLIC KEY-----
`
	key := OKPPublicKeyData{
		XCoord: pub,
		PublicKeyData: PublicKeyData{
			KeyType: int64(OctetKey),
		},
	}
	// Get the CBOR-encoded representation of the OKPPublicKeyData
	buf, _ := webauthncbor.Marshal(key)

	got := DisplayPublicKey(buf)
	if got != expected {
		t.Fatalf("incorrect PEM format received for ed25519 public key. expected\n%#v\n got \n%#v\n", expected, got)
	}
}
