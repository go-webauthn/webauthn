package protocol

import (
	"crypto"
	"crypto/ed25519"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// ptr returns a pointer to the given value. It exists so that the pointer-valued members of the extension output
// structures, where an absent value must be distinguishable from a false or zero value, can be constructed inline.
func ptr[T any](v T) *T {
	return &v
}

func mustParseX509Certificate(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return cert
}

func mustParseX509CertificatePEM(raw []byte) *x509.Certificate {
	block, rest := pem.Decode(raw)
	if len(rest) > 0 || block == nil || block.Type != "CERTIFICATE" {
		panic("Invalid PEM Certificate")
	}

	return mustParseX509Certificate(block.Bytes)
}

func attStatementParseX5CS(attStatement map[string]any, key string) (x5c []any, x5cs []*x509.Certificate, err error) {
	var ok bool
	if x5c, ok = attStatement[key].([]any); !ok {
		return nil, nil, ErrAttestationFormat.WithDetails("Error retrieving x5c value")
	}

	if len(x5c) == 0 {
		return nil, nil, ErrAttestationFormat.WithDetails("Error retrieving x5c value: empty array")
	}

	if x5cs, err = parseX5C(x5c); err != nil {
		return nil, nil, ErrAttestationFormat.WithDetails("Error retrieving x5c value: error occurred parsing values").WithError(err)
	}

	return x5c, x5cs, nil
}

// attestationCertAAGUID extracts the AAGUID from the id-fido-gen-ce-aaguid extension of an attestation certificate. The
// found return indicates the extension was present, and critical indicates it was marked as critical which some
// attestation statement formats explicitly forbid.
//
// Note that an X.509 Extension encodes the DER-encoding of the value in an OCTET STRING. Thus, the AAGUID is wrapped in
// two OCTET STRINGS to be valid.
func attestationCertAAGUID(cert *x509.Certificate) (aaguid []byte, critical, found bool, err error) {
	var raw []byte

	for _, extension := range cert.Extensions {
		if !extension.Id.Equal(oidFIDOGenCeAAGUID) {
			continue
		}

		found = true

		if extension.Critical {
			critical = true
		}

		raw = extension.Value
	}

	if len(raw) == 0 {
		return nil, critical, found, nil
	}

	if _, err = asn1.Unmarshal(raw, &aaguid); err != nil {
		return nil, critical, found, err
	}

	return aaguid, critical, found, nil
}

func parseX5C(x5c []any) (x5cs []*x509.Certificate, err error) {
	x5cs = make([]*x509.Certificate, len(x5c))

	var (
		raw []byte
		ok  bool
	)

	for i, t := range x5c {
		if raw, ok = t.([]byte); !ok {
			return nil, fmt.Errorf("x5c[%d] is not a byte array", i)
		}

		if x5cs[i], err = x509.ParseCertificate(raw); err != nil {
			return nil, fmt.Errorf("x5c[%d] is not a valid certificate: %w", i, err)
		}
	}

	return x5cs, nil
}

// attStatementCertChainVerify allows verifying an attestation statement certificate chain and optionally allows
// mangling the not after value for purpose of just validating the attestation lineage. If you set mangleNotAfter to
// true this function should only be considered safe for determining lineage, and not hte validity of a chain in
// general.
//
// WARNING: Setting mangleNotAfter=true weakens security by accepting expired certificates.
func attStatementCertChainVerify(certs []*x509.Certificate, roots *x509.CertPool, mangleNotAfter bool, mangleNotAfterSafeTime time.Time) (chains [][]*x509.Certificate, err error) {
	if len(certs) == 0 {
		return nil, errors.New("empty chain")
	}

	leaf := certInsecureConditionalNotAfterMangle(certs[0], mangleNotAfter, mangleNotAfterSafeTime)

	var (
		intermediates *x509.CertPool
	)

	staticRoots := roots != nil

	intermediates = x509.NewCertPool()

	if roots == nil {
		if roots, err = x509.SystemCertPool(); err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
	}

	// This skips the leaf by index rather than by identity as certInsecureConditionalNotAfterMangle returns a copy
	// when it mangles a certificate, which would make an identity comparison against the leaf never match.
	for i, cert := range certs {
		if i == 0 {
			continue
		}

		if isSelfSigned(cert) && !staticRoots {
			roots.AddCert(certInsecureConditionalNotAfterMangle(cert, mangleNotAfter, mangleNotAfterSafeTime))
		} else {
			intermediates.AddCert(certInsecureConditionalNotAfterMangle(cert, mangleNotAfter, mangleNotAfterSafeTime))
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,

		// Attestation certificates are not TLS certificates. An unset KeyUsages does not mean 'any': crypto/x509
		// substitutes ExtKeyUsageServerAuth and applies it to every certificate in the chain, rejecting attestation
		// certificates that carry any other Extended Key Usage, including ones it does not recognize such as
		// tcg-kp-AIKCertificate (2.23.133.8.3).
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	return leaf.Verify(opts)
}

func isSelfSigned(c *x509.Certificate) bool {
	if !c.IsCA {
		return false
	}

	return c.CheckSignatureFrom(c) == nil
}

// This function is used to intentionally but conditionally mangle the certificate not after value to exclude it from
// the verification process. This should only be used in instances where all you care about is which certificates
// performed the signing.
//
// WARNING: Setting mangle=true weakens security by accepting expired certificates.
func certInsecureConditionalNotAfterMangle(cert *x509.Certificate, mangle bool, safe time.Time) (out *x509.Certificate) {
	if !mangle || cert.NotAfter.After(time.Now().Add(time.Minute)) {
		return cert
	}

	out = &x509.Certificate{}

	*out = *cert

	out.NotAfter = safe

	return out
}

// verifyAttestationPublicKeyMatch verifies the credentialPublicKey of the attested credential data is the public key
// of the given attestation certificate, and returns the credential public key parsed from its COSE encoding so a
// signature made with it can be verified.
//
// The attestation statement formats which perform this step place no restriction on the key type, so every type the
// COSE parser produces is accepted rather than ECDSA alone.
func verifyAttestationPublicKeyMatch(att AttestationObject, cert *x509.Certificate) (credentialPublicKey any, err error) {
	if credentialPublicKey, err = webauthncose.ParsePublicKey(att.AuthData.AttData.CredentialPublicKey); err != nil {
		return nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error parsing public key: %+v", err)).WithError(err)
	}

	var public crypto.PublicKey

	if public, err = attestationCredentialPublicKey(credentialPublicKey); err != nil {
		return nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error converting public key: %+v", err)).WithError(err)
	}

	// Each standard library public key type carries an Equal method which reports false for a key of another type, so
	// a credential public key and a certificate public key of differing types are a mismatch rather than an error.
	equatable, ok := public.(interface{ Equal(x crypto.PublicKey) bool })
	if !ok {
		return nil, ErrInvalidAttestation.WithDetails("Public key does not support comparison")
	}

	if !equatable.Equal(cert.PublicKey) {
		return nil, ErrInvalidAttestation.WithDetails("Certificate public key does not match public key in authData")
	}

	return credentialPublicKey, nil
}

// attestationCredentialPublicKey converts a credential public key parsed from its COSE encoding into the equivalent
// standard library type.
func attestationCredentialPublicKey(credentialPublicKey any) (public crypto.PublicKey, err error) {
	switch k := credentialPublicKey.(type) {
	case webauthncose.EC2PublicKeyData:
		return k.ToECDSA()
	case webauthncose.RSAPublicKeyData:
		var exponent int

		if exponent, err = webauthncose.ParseRSAPublicKeyDataExponent(&k); err != nil {
			return nil, err
		}

		return &rsa.PublicKey{N: new(big.Int).SetBytes(k.Modulus), E: exponent}, nil
	case webauthncose.OKPPublicKeyData:
		// The coordinate is of the length ed25519 requires as webauthncose.ParsePublicKey rejects any other, so no
		// length is asserted here.
		return ed25519.PublicKey(k.XCoord), nil
	default:
		if public, ok, err := akpPublicKey(credentialPublicKey); ok {
			return public, err
		}

		return nil, fmt.Errorf("unsupported public key type %T", credentialPublicKey)
	}
}

// ValidateRPID performs non-exhaustive checks to ensure the string is most likely a domain string as
// relying-party ID's are required to be. Effectively this is localhost or a domain of two or more labels. The
// relying-party ID must not contain scheme, port, path, query, or fragment components, and must not be an IP
// address: §5.4.2 defines it as a valid domain string, which an address literal is not, and a client rejects one.
//
// No IDNA normalization is performed, so a value carrying non-ASCII characters is rejected rather than converted.
// A Relying Party ID is hashed verbatim to compare against the rpIdHash an authenticator reports, while a client
// normalizes the value it was handed, so a name which is not already in its ASCII form can never produce a matching
// hash. Callers serving an internationalized domain must apply IDNA themselves and configure the resulting A-label.
//
// See: https://www.w3.org/TR/webauthn/#rp-id
//
//nolint:gocyclo
func ValidateRPID(value string) (err error) {
	if len(value) == 0 {
		return errors.New("empty value provided")
	}

	if ip := net.ParseIP(value); ip != nil {
		return errDomainIsIPAddress
	}

	var rpid *url.URL

	if rpid, err = url.Parse(value); err != nil {
		return err
	}

	if rpid.Scheme != "" && rpid.Opaque != "" && rpid.Path == "" {
		return errors.New("the port component must be empty")
	}

	if rpid.Scheme != "" {
		if rpid.Host != "" && rpid.Path != "" {
			return errors.New("the path component must be empty")
		}

		if rpid.Host != "" && rpid.RawQuery != "" {
			return errors.New("the query component must be empty")
		}

		if rpid.Host != "" && rpid.Fragment != "" {
			return errors.New("the fragment component must be empty")
		}

		if rpid.Host != "" && rpid.Port() != "" {
			return errors.New("the port component must be empty")
		}

		return errors.New("the scheme component must be empty")
	}

	if rpid.RawQuery != "" {
		return errors.New("the query component must be empty")
	}

	if rpid.RawFragment != "" || rpid.Fragment != "" {
		return errors.New("the fragment component must be empty")
	}

	if rpid.Host == "" {
		if strings.Contains(rpid.Path, "/") {
			return errors.New("the path component must be empty")
		}
	}

	return validateDomainString(value)
}

func validateDomainString(value string) error {
	if len(value) > maxDomainLength {
		return errDomainTooLong
	}

	labels := strings.Split(value, ".")

	for _, label := range labels {
		if len(label) == 0 {
			return errDomainEmptyLabel
		}

		if len(label) > maxDomainLabelLength {
			return errDomainLabelTooLong
		}

		if label[0] == '-' || label[len(label)-1] == '-' {
			return errDomainLabelHyphen
		}

		if strings.ContainsAny(label, forbiddenDomainCodePoints) {
			return errDomainForbiddenCharacter
		}

		for _, r := range label {
			if r < 0x20 || r == 0x7F {
				return errDomainForbiddenCharacter
			}

			if r > 0x7F {
				return errDomainNotASCII
			}
		}
	}

	if isNumericDomainLabel(labels[len(labels)-1]) {
		return errDomainFinalLabelNumeric
	}

	if len(labels) == 1 && value != "localhost" {
		return errDomainNotADomain
	}

	return nil
}

func isNumericDomainLabel(label string) bool {
	if label == "" {
		return false
	}

	if strings.Trim(label, "0123456789") == "" {
		return true
	}

	_, err := strconv.ParseUint(label, 0, 64)

	return err == nil
}

// IsAttestationFormatString reports whether s is one of the WebAuthn-defined attestation statement format
// identifiers. Used to detect and migrate records from prior releases which stored
// the format string in the AttestationType field.
func IsAttestationFormatString(s string) bool {
	switch AttestationFormat(s) {
	case AttestationFormatPacked,
		AttestationFormatTPM,
		AttestationFormatAndroidKey,
		AttestationFormatAndroidSafetyNet,
		AttestationFormatFIDOUniversalSecondFactor,
		AttestationFormatApple,
		AttestationFormatCompound,
		AttestationFormatNone:
		return true
	default:
		return false
	}
}
