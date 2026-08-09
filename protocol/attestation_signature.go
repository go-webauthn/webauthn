package protocol

import (
	"crypto/ecdsa"
	"crypto/x509"
	"fmt"

	"github.com/go-webauthn/x/encoding/asn1"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// attestationCertCheckSignature verifies a signature over signed with the public key of cert, applying the encoding
// the policy selects to the signature beforehand.
//
// This is the [x509.Certificate.CheckSignature] of the attestation statement formats which verify their signature
// against a certificate. That method accepts only a DER encoded ECDSA signature and offers no way to relax it, so a
// signature the policy admits under another encoding is normalized to DER before it's handed over. Verification
// itself is left to the standard library so that the encoding is the only thing the policy alters.
func attestationCertCheckSignature(cert *x509.Certificate, algo x509.SignatureAlgorithm, signed, sig []byte, policy SignaturePolicy) (err error) {
	if sig, err = attestationSignatureEncode(cert.PublicKey, sig, policy); err != nil {
		return err
	}

	return cert.CheckSignature(algo, signed, sig)
}

// attestationKeyVerifySignature verifies a signature over signed with a credential public key parsed from its COSE
// encoding, applying the encoding the policy selects to the signature beforehand.
//
// This is the [webauthncose.VerifySignature] of the attestation statement formats which verify their signature
// against the credential public key, and exists so that the two ways an attestation signature is verified accept the
// same set of encodings under the same policy.
func attestationKeyVerifySignature(key any, signed, sig []byte, policy SignaturePolicy) (valid bool, err error) {
	if sig, err = attestationSignatureEncode(key, sig, policy); err != nil {
		return false, err
	}

	return webauthncose.VerifySignature(key, signed, sig)
}

// attestationSignatureEncode returns the signature in the encoding the verifiers require, which is DER for an ECDSA
// signature and the signature unaltered for every other key type.
//
// The signature is returned unaltered unless the policy admits an encoding a verifier doesn't, so the conforming
// policy reaches the verifier with exactly the bytes the authenticator produced. The key selects whether the
// signature is an ECDSA one, as that's what determines how the verifier will decode it.
func attestationSignatureEncode(key any, sig []byte, policy SignaturePolicy) (encoded []byte, err error) {
	if !policy.ECDSAEncoding.ber() || !attestationSignatureKeyIsECDSA(key) {
		return sig, nil
	}

	if encoded, err = asn1.NormalizeECDSASignature(sig); err != nil {
		return nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Signature validation error: %+v", err)).WithError(err)
	}

	return encoded, nil
}

// attestationSignatureKeyIsECDSA returns true when a signature made with the key is an ASN.1 encoded ECDSA
// signature. It accepts both the standard library key of a certificate and the credential public key produced by
// the COSE parser, as the signature of an attestation is verified against either.
func attestationSignatureKeyIsECDSA(key any) bool {
	switch key.(type) {
	case *ecdsa.PublicKey, ecdsa.PublicKey, webauthncose.EC2PublicKeyData, *webauthncose.EC2PublicKeyData:
		return true
	default:
		return false
	}
}
