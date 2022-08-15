//go:build go1.13

package webauthncose

import (
	"crypto/x509"

	"golang.org/x/crypto/ed25519"
)

func marshalEd25519PublicKey(pub ed25519.PublicKey) ([]byte, error) {
	return x509.MarshalPKIXPublicKey(pub)
}
