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

	// AKP is the key type for algorithm key pairs (i.e. ML-DSA).
	AKP
)
