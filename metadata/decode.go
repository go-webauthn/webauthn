package metadata

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/go-viper/mapstructure/v2"
	"github.com/golang-jwt/jwt/v5"

	"github.com/go-webauthn/x/revoke"
)

// NewDecoder returns a new metadata decoder.
func NewDecoder(opts ...DecoderOption) (decoder *Decoder, err error) {
	decoder = &Decoder{
		parser: jwt.NewParser(),
		hook:   mapstructure.ComposeDecodeHookFunc(),
	}

	for _, opt := range opts {
		if err = opt(decoder); err != nil {
			return nil, fmt.Errorf("failed to apply decoder option: %w", err)
		}
	}

	if decoder.root == "" {
		decoder.root = ProductionMDSRoot
	}

	return decoder, nil
}

// Decoder handles decoding and specialized parsing of the metadata blob.
type Decoder struct {
	parser                   *jwt.Parser
	hook                     mapstructure.DecodeHookFunc
	root                     string
	ignoreEntryParsingErrors bool
}

// Parse handles parsing of the raw JSON values of the metadata blob. Should be used after using [Decoder.Decode] or
// [Decoder.DecodeBytes].
func (d *Decoder) Parse(payload *PayloadJSON) (metadata *Metadata, err error) {
	metadata = &Metadata{
		Parsed: Parsed{
			LegalHeader: payload.LegalHeader,
			Number:      payload.Number,
		},
	}

	if metadata.Parsed.NextUpdate, err = time.Parse(time.DateOnly, payload.NextUpdate); err != nil {
		return nil, fmt.Errorf("error occurred parsing next update value '%s': %w", payload.NextUpdate, err)
	}

	var parsed Entry

	for _, entry := range payload.Entries {
		if parsed, err = entry.Parse(); err != nil {
			metadata.Unparsed = append(metadata.Unparsed, EntryError{
				Error:     err,
				EntryJSON: entry,
			})

			continue
		}

		metadata.Parsed.Entries = append(metadata.Parsed.Entries, parsed)
	}

	if n := len(metadata.Unparsed); n != 0 && !d.ignoreEntryParsingErrors {
		return metadata, fmt.Errorf("error occurred parsing metadata: %d entries had errors during parsing", n)
	}

	return metadata, nil
}

// Decode the blob from an [io.Reader]. The reader is read in full but is not closed; closing it remains the
// responsibility of the caller.
func (d *Decoder) Decode(r io.Reader) (payload *PayloadJSON, err error) {
	bytes, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return d.DecodeBytes(bytes)
}

// DecodeBytes handles decoding raw bytes. If you have a read closer it's suggested to use [Decoder.Decode].
func (d *Decoder) DecodeBytes(bytes []byte) (payload *PayloadJSON, err error) {
	var token *jwt.Token

	if token, err = d.parser.Parse(string(bytes), func(token *jwt.Token) (any, error) {
		// 2. If the x5u attribute is present in the JWT Header.
		if _, ok := token.Header[HeaderX509URI]; ok {
			// Never seen an x5u here, although it is in the spec.
			return nil, errors.New("x5u encountered in header of metadata TOC payload")
		}

		// 3. If the x5u attribute is missing, the chain should be retrieved from the x5c attribute.
		var (
			x5c, chain []any
			ok, valid  bool
		)

		if x5c, ok = token.Header[HeaderX509Certificate].([]any); !ok {
			// If that attribute is missing as well, Metadata TOC signing trust anchor is considered the TOC signing certificate chain.
			chain = []any{d.root}
		} else {
			chain = x5c
		}

		// The certificate chain MUST be verified to properly chain to the metadata TOC signing trust anchor.
		if valid, err = validateChain(d.root, chain); !valid || err != nil {
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

	payload = &PayloadJSON{}

	if decoder, err = mapstructure.NewDecoder(&mapstructure.DecoderConfig{
		Metadata:   nil,
		Result:     payload,
		DecodeHook: d.hook,
		TagName:    "json",
	}); err != nil {
		return nil, err
	}

	if err = decoder.Decode(token.Claims); err != nil {
		return payload, err
	}

	return payload, nil
}

// DecoderOption is a representation of a function that can set options within a decoder.
type DecoderOption func(decoder *Decoder) (err error)

// WithIgnoreEntryParsingErrors is a DecoderOption which ignores errors when parsing individual entries. The values for
// these entries will exist as an unparsed entry.
func WithIgnoreEntryParsingErrors() DecoderOption {
	return func(decoder *Decoder) (err error) {
		decoder.ignoreEntryParsingErrors = true

		return nil
	}
}

// WithRootCertificate overrides the root certificate used to validate the authenticity of the metadata payload.
func WithRootCertificate(value string) DecoderOption {
	return func(decoder *Decoder) (err error) {
		decoder.root = value

		return nil
	}
}

func validateChain(root string, chain []any) (bool, error) {
	if len(chain) == 0 {
		return false, errInvalidCertificateChain
	}

	// When no x5c header is present the caller sets chain = []any{root}, meaning
	// the trust anchor is itself the signing certificate. Allow that single-entry
	// fallback; reject any other single-entry chain as malformed.
	if len(chain) == 1 {
		entry, ok := chain[0].(string)
		if !ok || entry != root {
			return false, errInvalidCertificateChain
		}
		// Root is the signing cert; no further chain validation needed.
		return true, nil
	}

	// The chain is the signing certificate followed by every intermediate between it and the trust anchor. Each entry
	// is type checked before any of them are decoded so that a malformed chain is reported as such rather than as a
	// decoding failure of whichever entry happened to be handled first.
	encoded := make([]string, len(chain))

	for i, entry := range chain {
		value, ok := entry.(string)
		if !ok {
			return false, errInvalidCertificateChain
		}

		encoded[i] = value
	}

	rootcert, err := mdsParseX509Certificate(root)
	if err != nil {
		return false, err
	}

	roots := x509.NewCertPool()

	roots.AddCert(rootcert)

	ints := x509.NewCertPool()

	for _, value := range encoded[1:] {
		var intcert *x509.Certificate

		if intcert, err = mdsParseX509Certificate(value); err != nil {
			return false, err
		}

		if err = validateChainCheckRevocation(intcert, errIntermediateCertRevoked); err != nil {
			return false, err
		}

		ints.AddCert(intcert)
	}

	leafcert, err := mdsParseX509Certificate(encoded[0])
	if err != nil {
		return false, err
	}

	if err = validateChainCheckRevocation(leafcert, errLeafCertRevoked); err != nil {
		return false, err
	}

	opts := x509.VerifyOptions{
		Roots:         roots,
		Intermediates: ints,
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}

	_, err = leafcert.Verify(opts)

	return err == nil, err
}

func validateChainCheckRevocation(cert *x509.Certificate, revokedErr error) error {
	if revoked, ok := revoke.VerifyCertificate(cert); ok && revoked {
		return revokedErr
	}

	return nil
}

func mdsParseX509Certificate(value string) (certificate *x509.Certificate, err error) {
	var n int

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(value)))

	if n, err = base64.StdEncoding.Decode(raw, []byte(strings.TrimSpace(value))); err != nil {
		return nil, fmt.Errorf("error occurred parsing *x509.certificate: error occurred decoding base64 data: %w", err)
	}

	if certificate, err = x509.ParseCertificate(raw[:n]); err != nil {
		return nil, err
	}

	return certificate, nil
}

func mdsParseTimePointer(format, value string) (parsed *time.Time, err error) {
	if value == "" {
		return nil, nil
	}

	var p time.Time

	if p, err = time.Parse(format, value); err != nil {
		return nil, err
	}

	return &p, nil
}
