package protocol

// SignaturePolicy carries the Relying Party policy decisions for verifying the signatures of a ceremony. It applies
// to the attestation signature of a registration and to the assertion signature of an authentication alike, as an
// authenticator which deviates from the specification in how it encodes one generally does so in both. The zero
// value selects the behavior the specification requires.
type SignaturePolicy struct {
	// ECDSAEncoding selects the ASN.1 encodings which are accepted for an ECDSA signature.
	ECDSAEncoding ECDSASignatureEncoding
}

// ECDSASignatureEncoding selects the ASN.1 encodings which are accepted for an ECDSA signature.
//
// The specification requires a signature to be valid under the algorithm the ceremony names, and the registered
// ECDSA algorithms are defined over the DER encoding. Some authenticators nonetheless emit a signature whose
// integers carry the padding BER permits and DER forbids, which a conforming verifier rejects. Tolerating that
// encoding is a deviation from the specification rather than a choice it delegates, so it's offered here as a
// Relying Party decision with the conforming behavior as the default.
type ECDSASignatureEncoding int

const (
	// ECDSASignatureEncodingDefault is the zero value of [ECDSASignatureEncoding]. It evaluates as
	// [ECDSASignatureEncodingDER] wherever it is used. webauthn.Config rewrites it to that explicit constant during
	// validation, so a Relying Party can tell an unset field apart from a deliberate choice of the same encoding.
	ECDSASignatureEncodingDefault ECDSASignatureEncoding = iota

	// ECDSASignatureEncodingDER accepts only the DER encoding, which is the encoding the specification requires.
	ECDSASignatureEncodingDER

	// ECDSASignatureEncodingBER additionally accepts a signature whose integers are encoded under BER, by decoding
	// it and re-encoding the two integers it carries as DER before verification. Verification itself is unchanged:
	// the same signature over the same data by the same key is required, and only the encoding the verifier is
	// handed differs.
	//
	// The relaxation is confined to the minimal encoding requirement DER places on an INTEGER. A signature which is
	// not a SEQUENCE of exactly two positive integers, which carries a non-minimal or indefinite length, or which
	// has trailing data is rejected under this encoding as it is under [ECDSASignatureEncodingDER]. A signature
	// which cannot be decoded fails the ceremony rather than being passed on to be verified unchanged.
	//
	// This is insecure and not recommended. Accepting a non-DER signature makes the encoding of a signature
	// malleable, in that byte sequences which are not equal verify against the same message, and it accepts an
	// authenticator which does not conform to the specification. Select it only where a population of
	// authenticators known to emit such signatures has to be supported.
	ECDSASignatureEncodingBER
)

// ber returns true when the encoding accepts an ECDSA signature whose integers are encoded under BER. Every other
// value, including the zero value and any value outside the defined set, accepts DER alone so that an unset or
// malformed policy is the conforming one.
func (e ECDSASignatureEncoding) ber() bool {
	return e == ECDSASignatureEncodingBER
}
