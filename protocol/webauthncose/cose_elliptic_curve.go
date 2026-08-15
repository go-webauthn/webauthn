package webauthncose

import "strconv"

// COSEEllipticCurve is an enumerator that represents the COSE Elliptic Curves.
//
// Specification: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
type COSEEllipticCurve int

const (
	// EllipticCurveReserved is the COSE EC Reserved value.
	EllipticCurveReserved COSEEllipticCurve = iota

	// P256 represents NIST P-256 also known as secp256r1.
	P256

	// P384 represents NIST P-384 also known as secp384r1.
	P384

	// P521 represents NIST P-521 also known as secp521r1.
	P521

	// X25519 for use w/ ECDH only.
	X25519

	// X448 for use w/ ECDH only.
	X448

	// Ed25519 for use w/ EdDSA only.
	Ed25519

	// Ed448 for use w/ EdDSA only.
	Ed448

	// Secp256k1 is the SECG secp256k1 curve.
	Secp256k1
)

// String returns the name under which the curve is registered, falling back to its numeric identifier for a curve
// this library does not model.
//
// Registry: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
func (c COSEEllipticCurve) String() string {
	if name, ok := coseEllipticCurveNames[c]; ok {
		return name
	}

	return strconv.Itoa(int(c))
}

// coseEllipticCurveNames maps each curve this library models to the name under which it is registered, backing
// [COSEEllipticCurve.String].
//
// Registry: https://www.iana.org/assignments/cose/cose.xhtml#elliptic-curves
var coseEllipticCurveNames = map[COSEEllipticCurve]string{
	P256:      "P-256",
	P384:      "P-384",
	P521:      "P-521",
	X25519:    "X25519",
	X448:      "X448",
	Ed25519:   "Ed25519",
	Ed448:     "Ed448",
	Secp256k1: "secp256k1",
}
