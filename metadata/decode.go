package metadata

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/go-webauthn/x/revoke"
	"github.com/golang-jwt/jwt/v5"
	"github.com/mitchellh/mapstructure"
	"io"
	"net/http"
	"strings"
	"time"
)

// NewDecoder returns a new metadata decoder.
func NewDecoder(opts ...DecoderOption) (decoder *Decoder) {
	decoder = &Decoder{
		client: &http.Client{},
		parser: jwt.NewParser(),
		hook:   mapstructure.ComposeDecodeHookFunc(),
	}

	for _, opt := range opts {
		opt(decoder)
	}

	return decoder
}

type Decoder struct {
	client           *http.Client
	parser           *jwt.Parser
	hook             mapstructure.DecodeHookFunc
	skipParserErrors bool
}

func (d *Decoder) Parse(payload *MetadataBLOBPayloadJSON) (metadata *Metadata, err error) {
	metadata = &Metadata{
		Parsed: MetadataBLOBPayload{
			LegalHeader: payload.LegalHeader,
			Number:      payload.Number,
		},
	}

	if metadata.Parsed.NextUpdate, err = time.Parse(time.DateOnly, payload.NextUpdate); err != nil {
		return nil, fmt.Errorf("error occurred parsing next update value: %w", err)
	}

	var parsed MetadataBLOBPayloadEntry

	for _, entry := range payload.Entries {
		if parsed, err = entry.Parse(); err != nil {
			metadata.Unparsed = append(metadata.Unparsed, MetadataBLOBPayloadEntryError{
				Error:                        err,
				MetadataBLOBPayloadEntryJSON: entry,
			})

			continue
		}

		metadata.Parsed.Entries = append(metadata.Parsed.Entries, parsed)
	}

	if n := len(metadata.Unparsed); n != 0 && !d.skipParserErrors {
		return metadata, fmt.Errorf("error occured parsing metadata: %d entries had errors during parsing", n)
	}

	return metadata, nil
}

func (d *Decoder) Decode(r io.ReadCloser) (payload *MetadataBLOBPayloadJSON, err error) {
	defer r.Close()

	bytes, err := io.ReadAll(r)
	if err != nil {
		return nil, err
	}

	return d.DecodeBytes(bytes)
}

func (d *Decoder) DecodeBytes(bytes []byte) (payload *MetadataBLOBPayloadJSON, err error) {
	payload = &MetadataBLOBPayloadJSON{}

	var token *jwt.Token

	if token, err = d.parser.Parse(string(bytes), func(token *jwt.Token) (any, error) {
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

const x = `
// 95e4d58c-056e-4a65-866d-f5a69659e880 / TruU Windows Authenticator:
-----BEGIN CERTIFICATE-----
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUNTekNDQWZLZ0F3SUJBZ0lV
VzNYSzh5eXdiQVdsaWdsaXhJRjYzZHZxWXk4d0NnWUlLb1pJemowRUF3SXcKZkRF
TE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ01DRU52Ykc5eVlXUnZNUTh3RFFZ
RFZRUUhEQVpFWlc1MgpaWEl4RXpBUkJnTlZCQW9NQ2xSeWRWVXNJRWx1WXk0eElq
QWdCZ05WQkFzTUdVRjFkR2hsYm5ScFkyRjBiM0lnClFYUjBaWE4wWVhScGIyNHhF
REFPQmdOVkJBTU1CM1J5ZFhVdVlXa3dJQmNOTWpNeE1UQXpNakF6TmpVeFdoZ1AK
TWpBMU16RXdNall5TURNMk5URmFNSHd4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lE
VlFRSURBaERiMnh2Y21GawpiekVQTUEwR0ExVUVCd3dHUkdWdWRtVnlNUk13RVFZ
RFZRUUtEQXBVY25WVkxDQkpibU11TVNJd0lBWURWUVFMCkRCbEJkWFJvWlc1MGFX
TmhkRzl5SUVGMGRHVnpkR0YwYVc5dU1SQXdEZ1lEVlFRRERBZDBjblYxTG1GcE1G
a3cKRXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVOQXZidGNjTXI3ai9T
UldtcUlFWlRSV05KeWo2bXNZcgo1bEdlQWdkU0d5QzlPMDM1NlJJZWN1YVZpT3F6
MER4Z1MxZi81S1BiWnAxdDB5RDJmVlJYOTZOUU1FNHdIUVlEClZSME9CQllFRkE1
dEwxMGc4OHQycVhsUGxoSVNJMmRJemxhVk1COEdBMVVkSXdRWU1CYUFGQTV0TDEw
Zzg4dDIKcVhsUGxoSVNJMmRJemxhVk1Bd0dBMVVkRXdFQi93UUNNQUF3Q2dZSUtv
Wkl6ajBFQXdJRFJ3QXdSQUlnWGZ1dgpqc3ArNHY1aUdPcW5nVWdPZzFobWJnRlBG
TWdJanlXeENLcXcvZDhDSUZpbUxOWExESXdBK29JYlAxeU9mcUU4CnhrNnE3LzRM
V09WWWtSQUxvQkMyCi0tLS0tRU5EIENFUlRJRklDQVRFLS0tLS0=
-----END CERTIFICATE-----

// 4c0cf95d-2f40-43b5-ba42-4c83a11c04ba / Feitian BioPass FIDO2 Pro Authenticator
-----BEGIN CERTIFICATE-----
MIIB2TCCAX6gAwIBAgIQFQNKW+7zbg/7d+lTyrIWwDAKBggqhkjOPQQDAjBLMQsw
CQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNV
BAMMFEZlaXRpYW4gRklETyBSb290IENBMCAXDTIyMDYwODAwMDAwMFoYDzIwNTIw
NjA3MjM1OTU5WjBLMQswCQYDVQQGEwJVUzEdMBsGA1UECgwURmVpdGlhbiBUZWNo
bm9sb2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEsFYEEhiJuqqnMgQjSiivBjV7DGCTf4XBBH/B7uvZ
sKxXShF0L8uDISWUvcExixRs6gB3oldSrjox6L8T94NOzqNCMEAwHQYDVR0OBBYE
FEu9hyYRrRyJzwRYvnDSCIxrFiO3MA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/
BAQDAgEGMAoGCCqGSM49BAMCA0kAMEYCIQCB0NFQSN0z4lWz/yc36ewrTCzttK/q
FvlaPOKh+T1o6wIhAP0oKKA+cicsDy3Y3n+VlP8eB3PBzMkhvW/9ISXCw+VBMIIB
2DCCAX6gAwIBAgIQBTmk3ZwilFXjsZywHDnMgDAKBggqhkjOPQQDAjBLMQswCQYD
VQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9sb2dpZXMxHTAbBgNVBAMM
FEZlaXRpYW4gRklETyBSb290IENBMCAXDTIyMDYwODAwMDAwMFoYDzIwNTIwNjA3
MjM1OTU5WjBLMQswCQYDVQQGEwJDTjEdMBsGA1UECgwURmVpdGlhbiBUZWNobm9s
b2dpZXMxHTAbBgNVBAMMFEZlaXRpYW4gRklETyBSb290IENBMFkwEwYHKoZIzj0C
AQYIKoZIzj0DAQcDQgAEnfAKbjvMX1Ey1b6k+WQQdNVMt9JgGWyJ3PvM4BSK5XqT
fo++0oAj/4tnwyIL0HFBR9St+ktjqSXDfjiXAurs86NCMEAwHQYDVR0OBBYEFNGh
mE2Bf8O5a/YHZ71QEv6QRfFUMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQD
AgEGMAoGCCqGSM49BAMCA0gAMEUCIByRz4OAlRZ9Hz9KV7g2QNtC0C8JxH/xLJY8
FZEmtJ3sAiEAsreT0+eNkNcUjI9h5OPCoH6NmsOkgvEABJZrF07ADkY=
-----END CERTIFICATE-----

// ca87cb70-4c1b-4579-a8e8-4efdd7c007e0 / FIDO Alliance TruU Sample FIDO2 Authenticator
-----BEGIN CERTIFICATE-----
LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSURYekNDQWtlZ0F3SUJBZ0lM
QkFBQUFBQUJJVmhUQ0tJd0RRWUpLb1pJaHZjTkFRRUxCUUF3VERFZ01CNEcKQTFV
RUN4TVhSMnh2WW1Gc1UybG5iaUJTYjI5MElFTkJJQzBnVWpNeEV6QVJCZ05WQkFv
VENrZHNiMkpoYkZOcApaMjR4RXpBUkJnTlZCQU1UQ2tkc2IySmhiRk5wWjI0d0ho
Y05NRGt3TXpFNE1UQXdNREF3V2hjTk1qa3dNekU0Ck1UQXdNREF3V2pCTU1TQXdI
Z1lEVlFRTEV4ZEhiRzlpWVd4VGFXZHVJRkp2YjNRZ1EwRWdMU0JTTXpFVE1CRUcK
QTFVRUNoTUtSMnh2WW1Gc1UybG5iakVUTUJFR0ExVUVBeE1LUjJ4dlltRnNVMmxu
YmpDQ0FTSXdEUVlKS29aSQpodmNOQVFFQkJRQURnZ0VQQURDQ0FRb0NnZ0VCQU13
bGRwQjVCbmdpRnZYQWc3YUV5aWllL1FWMkVjV3RpSEw4ClJnSkR4N0tLblFSZkpN
c3VTK0ZnZ2tiaFVxc01nVWR3Yk4xazBldjFMS01QZ2owTUs2NlgxN1lVaGhCNXV6
c1QKZ0hlTUNPRkowbXBpTHg5ZStwWm8zNGtubFRpZkJ0Yyt5Y3NtV1ExejNyREk2
U1lPZ3hYRzcxdUwwZ1JneWttbQpLUFpwTy9iTHlDaVI1WjJLWVZjM3JIUVUzSFRn
T3U1eUx5NmMrOUM3di9VOUFPRUdNK2lDSzY1VHBqb1djNHpkClFRNGdPc0MwcDZI
cHNrK1FMakpnNlZmTHVRU1NhR2psT0NaZ2RiS2ZkLytSRk8rdUlFbjhyVUFWU05F
Q01XRVoKWHJpWDc2MTN0MlNhZXI5ZndSUHZtMkw3RFd6Z1ZHa1dxUVBhYnVtRGsz
RjJ4bW1GZ2hjQ0F3RUFBYU5DTUVBdwpEZ1lEVlIwUEFRSC9CQVFEQWdFR01BOEdB
MVVkRXdFQi93UUZNQU1CQWY4d0hRWURWUjBPQkJZRUZJL3dTMytvCkxrVWtyazFR
K21PYWk5N2kzUnU4TUEwR0NTcUdTSWIzRFFFQkN3VUFBNElCQVFCTFFOdkFVS3Ir
eUF6djk1WlUKUlVtN2xnQUpRYXl6RTRhR0tBY3p5bXZtZExtNkFDMnVwQXJUOWZI
eEQ0cS9jMmRLZzhkRWUzamdyMjVzYndNcApqak01UmNPTzVMbFhiS3I4RXBic1U4
WXQ1Q1JzdVpSais5eFRhR2RXUG9PNHp6VWh3OGxvL3M3YXdsT3F6SkNLCjZmQmRS
b3lWM1hwWUtCb3ZIZDdOQURkQmorMUViZGRUS0pkKzgyY0VIaFhYaXBhMDA5NU1K
NlJNRzNOemR2UVgKbWNJZmVnN2pMUWl0Q2h3cy96eXJWUTRQa1g0MjY4TlhTYjdo
TGkxOFlJdkRRVkVUSTUzTzl6SnJsQUdvbWVjcwpNeDg2T3lYU2hrRE9PeXlHZU1s
aEx4UzY3dHRWYjkrRTdnVUpUYjBvMkhMTzAySlFaUjdya3BlRE1kbXp0Y3BICldE
OWYKLS0tLS1FTkQgQ0VSVElGSUNBVEUtLS0tLQ==
-----END CERTIFICATE-----
`

func ParseMetadataX509Certificate(value string) (certificate *x509.Certificate, err error) {
	var n int

	raw := make([]byte, base64.StdEncoding.DecodedLen(len(value)))

	if n, err = base64.StdEncoding.Decode(raw, []byte(strings.TrimSpace(value))); err != nil {
		return nil, fmt.Errorf("error occurred parsing *x509.certificate: error occurred decoding base64 data: %w", err)
	}

	if certificate, err = x509.ParseCertificate(raw[:n]); err != nil {
		fmt.Println("failed to parse cert", value)
		return nil, err
	}

	return certificate, nil
}

type DecoderOption func(decoder *Decoder)

func WithSkipParserErrors() DecoderOption {
	return func(decoder *Decoder) {
		decoder.skipParserErrors = true
	}
}
