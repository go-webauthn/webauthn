package webauthncose

// COSEKeyType is The Key type derived from the IANA COSE AuthData.
type COSEKeyType int

const (
	// KeyTypeReserved is a reserved value.
	KeyTypeReserved COSEKeyType = iota

	// OctetKey is an Octet Key.
	OctetKey

	// EllipticKey is an Elliptic Curve Public Key.
	EllipticKey

	// RSAKey is an RSA Public Key.
	RSAKey

	// Symmetric Keys.
	Symmetric

	// HSSLMS is the public key for HSS/LMS hash-based digital signature.
	HSSLMS

	// WalnutDSA is the public key for Walnut Digital Signature Algorithm.
	WalnutDSA

	// AKP is the key type for algorithm key pairs, which carry their key material as an opaque byte string whose
	// interpretation is left to the algorithm the key names. This library uses it for the ML-DSA parameter sets.
	//
	// Specification: §6. COSE Key Type AKP (https://www.rfc-editor.org/rfc/rfc9964#section-6)
	AKP
)
