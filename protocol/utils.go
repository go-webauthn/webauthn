package protocol

import (
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"time"
)

func MustParseX509Certificate(der []byte) *x509.Certificate {
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		panic(err)
	}

	return cert
}

func MustParseX509CertificatePEM(raw []byte) *x509.Certificate {
	block, rest := pem.Decode(raw)
	if len(rest) > 0 || block == nil || block.Type != "CERTIFICATE" {
		panic("Invalid PEM Certificate")
	}

	return MustParseX509Certificate(block.Bytes)
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

func certChainVerify(certs []*x509.Certificate, roots *x509.CertPool, mangleNotAfter bool, mangleNotAfterSafeTime time.Time) (chains [][]*x509.Certificate, err error) {
	if len(certs) == 0 {
		return nil, errors.New("empty chain")
	}

	leaf := certs[0]

	for _, cert := range certs {
		if !cert.IsCA {
			if mangleNotAfter {
				leaf = certInsecureNotAfterMangle(cert, mangleNotAfterSafeTime)
			} else {
				leaf = cert
			}

			break
		}
	}

	var (
		intermediates *x509.CertPool
	)

	intermediates = x509.NewCertPool()

	if roots == nil {
		if roots, err = x509.SystemCertPool(); err != nil || roots == nil {
			roots = x509.NewCertPool()
		}
	}

	for _, cert := range certs {
		if cert == leaf {
			continue
		}

		if mangleNotAfter {
			if isSelfSigned(cert) {
				roots.AddCert(certInsecureNotAfterMangle(cert, mangleNotAfterSafeTime))
			} else {
				intermediates.AddCert(certInsecureNotAfterMangle(cert, mangleNotAfterSafeTime))
			}
		} else {
			if isSelfSigned(cert) {
				roots.AddCert(cert)
			} else {
				intermediates.AddCert(cert)
			}
		}
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: intermediates,
	}

	return leaf.Verify(opts)
}

func isSelfSigned(c *x509.Certificate) bool {
	// Cheap check (Subject == Issuer) + cryptographic check.
	if !c.IsCA {
		return false
	}
	return c.CheckSignatureFrom(c) == nil
}

// This function is used to intentionally mangle the certificates not after values to exclude them from
// the verification process. This should only be used in instances where all you care about is which certificates
// performed the signing.
func certsInsecureNotAfterMangle(certs []*x509.Certificate) (out []*x509.Certificate) {
	// Add 1 year to the current time. This is effectively the not after time which is used to determine which
	// certificates to mangle.
	safe := time.Now().Add(time.Hour * 8760).UTC()

	out = make([]*x509.Certificate, len(certs))

	for i, cert := range certs {
		out[i] = certInsecureNotAfterMangle(cert, safe)
	}

	return out
}

// This function is used to intentionally mangle the certificate not after value to exclude it from
// the verification process. This should only be used in instances where all you care about is which certificates
// performed the signing.
func certInsecureNotAfterMangle(cert *x509.Certificate, safe time.Time) (out *x509.Certificate) {
	c := *cert

	out = &c

	if out.NotAfter.Before(safe) {
		out.NotAfter = safe
	}

	return out
}

func certsToCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()

	for _, cert := range certs {
		pool.AddCert(cert)
	}

	return pool
}
