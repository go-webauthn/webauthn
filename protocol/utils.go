package protocol

import (
	"crypto/x509"
	"encoding/pem"
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

// This function is used to intentionally mangle the certificates not before and not after values to exclude them from
// the verification process. This should only be used in instances where the all you care about is which certificates
// performed the signing.
func insecureMangleCertsNotAfter(certs []*x509.Certificate) (out []*x509.Certificate) {
	// Add 1 year to the current time. This is effectively the not after time which is used to determine which
	// certificates to mangle.
	safe := time.Now().Add(time.Hour * 8760).UTC()

	out = make([]*x509.Certificate, len(certs))

	for i, cert := range certs {
		c := *cert

		out[i] = &c

		if out[i].NotAfter.Before(safe) {
			out[i].NotAfter = safe
		}
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
