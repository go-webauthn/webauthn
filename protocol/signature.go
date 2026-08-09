package protocol

import (
	"crypto/ecdsa"
	"crypto/x509"

	"github.com/go-webauthn/x/encoding/asn1"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// certCheckSignature verifies a signature over signed with the public key of cert, applying the encoding the policy
// selects to the signature beforehand.
//
// This is the [x509.Certificate.CheckSignature] of the ceremonies which verify a signature against a certificate.
// That method accepts only a DER encoded ECDSA signature and offers no way to relax it, so a signature the policy
// admits under another encoding is normalized to DER before it's handed over. Verification itself is left to the
// standard library so that the encoding is the only thing the policy alters.
//
// The error is returned unwrapped so the caller can describe it in the terms of the ceremony it's verifying.
func certCheckSignature(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, sig []byte, policy SignaturePolicy) (err error) {
	if sig, err = signatureEncode(cert.PublicKey, sig, policy); err != nil {
		return err
	}

	return cert.CheckSignature(algo, signed, sig)
}

// keyVerifySignature verifies a signature over signed with a public key parsed from its COSE encoding, applying the
// encoding the policy selects to the signature beforehand.
//
// This is the [webauthncose.VerifySignature] of the ceremonies which verify a signature against a credential public
// key, and exists so that every way a signature is verified accepts the same set of encodings under the same policy.
func keyVerifySignature(key any, signed, sig []byte, policy SignaturePolicy) (valid bool, err error) {
	if sig, err = signatureEncode(key, sig, policy); err != nil {
		return false, err
	}

	return webauthncose.VerifySignature(key, signed, sig)
}

// signatureEncode returns the signature in the encoding the verifiers require, which is DER for an ECDSA signature
// and the signature unaltered for every other key type.
//
// The signature is returned unaltered unless the policy admits an encoding a verifier doesn't, so the conforming
// policy reaches the verifier with exactly the bytes the authenticator produced. The key selects whether the
// signature is an ECDSA one, as that's what determines how the verifier will decode it.
func signatureEncode(key any, sig []byte, policy SignaturePolicy) (encoded []byte, err error) {
	if !policy.ECDSAEncoding.ber() || !signatureKeyIsECDSA(key) {
		return sig, nil
	}

	return asn1.NormalizeECDSASignature(sig)
}

// signatureKeyIsECDSA returns true when a signature made with the key is an ASN.1 encoded ECDSA signature. It
// accepts both the standard library key of a certificate and the credential public key produced by the COSE parser,
// as a signature is verified against either.
func signatureKeyIsECDSA(key any) bool {
	switch key.(type) {
	case *ecdsa.PublicKey, ecdsa.PublicKey, webauthncose.EC2PublicKeyData, *webauthncose.EC2PublicKeyData:
		return true
	default:
		return false
	}
}
