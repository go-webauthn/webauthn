package metadata

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/x/revoke"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
)

// NewDecoder returns a new metadata decoder.
func NewDecoder() (decoder *Decoder) {
	return &Decoder{
		client: &http.Client{},
		parser: jwt.NewParser(),
		hook:   mapstructure.ComposeDecodeHookFunc(),
	}
}

type Decoder struct {
	client *http.Client
	parser *jwt.Parser
	hook   mapstructure.DecodeHookFunc
}

func (d *Decoder) Decode(blob []byte) (payload *MetadataBLOBPayloadJSON, err error) {
	payload = &MetadataBLOBPayloadJSON{}

	var token *jwt.Token

	if token, err = d.parser.Parse(string(blob), func(token *jwt.Token) (any, error) {
		// 2. If the x5u attribute is present in the JWT Header, then
		if _, ok := token.Header[HeaderX509URI].([]any); ok {
			// never seen an x5u here, although it is in the spec
			return nil, errors.New("x5u encountered in header of metadata TOC payload")
		}

		// 3. If the x5u attribute is missing, the chain should be retrieved from the x5c attribute.
		var (
			x5c, chain []any
			ok, valid  bool
		)

		if x5c, ok = token.Header[HeaderX509Certificate].([]any); !ok {
			// If that attribute is missing as well, Metadata TOC signing trust anchor is considered the TOC signing certificate chain.
			chain[0] = MDSRoot
		} else {
			chain = x5c
		}

		// The certificate chain MUST be verified to properly chain to the metadata TOC signing trust anchor.
		if valid, err = validateChain(chain, d.client); !valid || err != nil {
			return nil, err
		}

		// Chain validated, extract the TOC signing certificate from the chain. Create a buffer large enough to hold the
		// certificate bytes.
		o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))

		var (
			n    int
			cert *x509.Certificate
		)

		// Decode the base64 certificate into the buffer.
		if n, err = base64.StdEncoding.Decode(o, []byte(chain[0].(string))); err != nil {
			return nil, err
		}

		// Parse the certificate from the buffer.
		if cert, err = x509.ParseCertificate(o[:n]); err != nil {
			return nil, err
		}

		// 4. Verify the signature of the Metadata TOC object using the TOC signing certificate chain
		// jwt.Parse() uses the TOC signing certificate public key internally to verify the signature.
		return cert.PublicKey, err
	}); err != nil {
		return nil, err
	}

	var decoder *mapstructure.Decoder

	if decoder, err = mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata:   nil,
		Result:     payload,
		DecodeHook: d.hook,
	}); err != nil {
		return nil, err
	}

	if err = decoder.Decode(token.Claims); err != nil {
		return payload, err
	}

	return payload, nil
}

func unmarshalMDSBLOB(body []byte, c *http.Client) (MetadataBLOBPayloadJSON, error) {
	var payload MetadataBLOBPayloadJSON

	token, err := jwt.Parse(string(body), func(token *jwt.Token) (any, error) {
		// 2. If the x5u attribute is present in the JWT Header, then
		if _, ok := token.Header[HeaderX509URI].([]any); ok {
			// never seen an x5u here, although it is in the spec
			return nil, errors.New("x5u encountered in header of metadata TOC payload")
		}
		var chain []any
		// 3. If the x5u attribute is missing, the chain should be retrieved from the x5c attribute.

		if x5c, ok := token.Header[HeaderX509Certificate].([]any); !ok {
			// If that attribute is missing as well, Metadata TOC signing trust anchor is considered the TOC signing certificate chain.
			chain[0] = MDSRoot
		} else {
			chain = x5c
		}

		// The certificate chain MUST be verified to properly chain to the metadata TOC signing trust anchor.
		valid, err := validateChain(chain, c)
		if !valid || err != nil {
			return nil, err
		}

		// Chain validated, extract the TOC signing certificate from the chain. Create a buffer large enough to hold the
		// certificate bytes.
		o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))

		// base64 decode the certificate into the buffer.
		n, err := base64.StdEncoding.Decode(o, []byte(chain[0].(string)))
		if err != nil {
			return nil, err
		}

		// Parse the certificate from the buffer.
		cert, err := x509.ParseCertificate(o[:n])
		if err != nil {
			return nil, err
		}

		// 4. Verify the signature of the Metadata TOC object using the TOC signing certificate chain
		// jwt.Parse() uses the TOC signing certificate public key internally to verify the signature.
		return cert.PublicKey, err
	})

	if err != nil {
		return payload, err
	}

	err = mapstructure.Decode(token.Claims, &payload)

	return payload, err
}

func validateChain(chain []any, c *http.Client) (bool, error) {
	oRoot := make([]byte, base64.StdEncoding.DecodedLen(len(MDSRoot)))

	nRoot, err := base64.StdEncoding.Decode(oRoot, []byte(MDSRoot))
	if err != nil {
		return false, err
	}

	rootcert, err := x509.ParseCertificate(oRoot[:nRoot])
	if err != nil {
		return false, err
	}

	roots := x509.NewCertPool()

	roots.AddCert(rootcert)

	o := make([]byte, base64.StdEncoding.DecodedLen(len(chain[1].(string))))

	n, err := base64.StdEncoding.Decode(o, []byte(chain[1].(string)))
	if err != nil {
		return false, err
	}

	intcert, err := x509.ParseCertificate(o[:n])
	if err != nil {
		return false, err
	}

	if revoked, ok := revoke.VerifyCertificate(intcert); !ok {
		issuer := intcert.IssuingCertificateURL

		if issuer != nil {
			return false, errCRLUnavailable
		}
	} else if revoked {
		return false, errIntermediateCertRevoked
	}

	ints := x509.NewCertPool()
	ints.AddCert(intcert)

	l := make([]byte, base64.StdEncoding.DecodedLen(len(chain[0].(string))))

	n, err = base64.StdEncoding.Decode(l, []byte(chain[0].(string)))
	if err != nil {
		return false, err
	}

	leafcert, err := x509.ParseCertificate(l[:n])
	if err != nil {
		return false, err
	}

	if revoked, ok := revoke.VerifyCertificate(leafcert); !ok {
		return false, errCRLUnavailable
	} else if revoked {
		return false, errLeafCertRevoked
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,
	}

	_, err = leafcert.Verify(opts)

	return err == nil, err
}

func ParseMetadataX509Certificate(value string) (certificate *x509.Certificate, err error) {
	var n int

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(value)))

	if n, err = base64.StdEncoding.Decode(raw, []byte(value)); err != nil {
		return nil, fmt.Errorf("error occurred parsing *x509.certificate: error occurred decoding base64 data: %w", err)
	}

	if certificate, err = x509.ParseCertificate(raw[:n]); err != nil {
		fmt.Println(err)

		return nil, nil
		//return nil, fmt.Errorf("error occurred parsing *x509.certificate: error occurred parsing certificate: %w", err)
	}

	return certificate, nil
}
