package protocol

import (
	"bytes"
	"crypto/subtle"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"

	"github.com/google/go-tpm/tpm2"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// attestationFormatValidationHandlerTPM is the handler for the TPM Attestation Statement Format.
//
// The syntax of a TPM Attestation statement is as follows:
//
// $$attStmtType // = (
//
//	    fmt: "tpm",
//	    attStmt: tpmStmtFormat
//	)
//
//	tpmStmtFormat = {
//	                    ver: "2.0",
//	                    (
//	                        alg: COSEAlgorithmIdentifier,
//	                        x5c: [ aikCert: bytes, * (caCert: bytes) ]
//	                    )
//	                    sig: bytes,
//	                    certInfo: bytes,
//	                    pubArea: bytes
//	                }
//
// Specification: §8.3. TPM Attestation Statement Format
//
// See: https://www.w3.org/TR/webauthn/#sctn-tpm-attestation
//
//nolint:gocyclo
func attestationFormatValidationHandlerTPM(att AttestationObject, clientDataHash []byte, _ metadata.Provider, policy AttestationPolicy, signature SignaturePolicy) (attestationType string, x5cs []any, err error) {
	var statement *tpm2AttStatement

	if statement, err = newTPM2AttStatement(att.AttStatement); err != nil {
		return "", nil, err
	}

	if statement.HasECDAAKeyID || statement.HasValidECDAAKeyID {
		return "", nil, ErrNotImplemented
	}

	if !statement.HasX5C || !statement.HasValidX5C {
		return "", nil, ErrNotImplemented
	}

	if statement.Version != versionTPM20 {
		return "", nil, ErrAttestationFormat.WithDetails("WebAuthn only supports TPM 2.0 currently")
	}

	var (
		pubArea *tpm2.TPMTPublic
		key     any
	)

	if pubArea, err = tpm2.Unmarshal[tpm2.TPMTPublic](statement.PubArea); err != nil {
		return "", nil, ErrAttestationFormat.WithDetails("Unable to decode TPMT_PUBLIC in attestation statement").WithError(err)
	}

	if key, err = webauthncose.ParsePublicKey(att.AuthData.AttData.CredentialPublicKey); err != nil {
		return "", nil, err
	}

	switch k := key.(type) {
	case webauthncose.EC2PublicKeyData:
		var (
			params *tpm2.TPMSECCParms
			point  *tpm2.TPMSECCPoint
		)

		if params, err = pubArea.Parameters.ECCDetail(); err != nil {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between ECCParameters in pubArea and credentialPublicKey")
		}

		if point, err = pubArea.Unique.ECC(); err != nil {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between ECCParameters in pubArea and credentialPublicKey")
		}

		if params.CurveID != k.TPMCurveID() {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between ECCParameters in pubArea and credentialPublicKey")
		}

		if !bytes.Equal(point.X.Buffer, k.XCoord) || !bytes.Equal(point.Y.Buffer, k.YCoord) {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between ECCParameters in pubArea and credentialPublicKey")
		}
	case webauthncose.RSAPublicKeyData:
		var (
			params  *tpm2.TPMSRSAParms
			modulus *tpm2.TPM2BPublicKeyRSA
		)

		if params, err = pubArea.Parameters.RSADetail(); err != nil {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between RSAParameters in pubArea and credentialPublicKey")
		}

		if modulus, err = pubArea.Unique.RSA(); err != nil {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between RSAParameters in pubArea and credentialPublicKey")
		}

		if !bytes.Equal(modulus.Buffer, k.Modulus) {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between RSAParameters in pubArea and credentialPublicKey")
		}

		var e int

		if e, err = webauthncose.ParseRSAPublicKeyDataExponent(&k); err != nil {
			return "", nil, ErrAttestationFormat.WithDetails("Unable to decode RSA exponent in attestation statement").WithError(err)
		} else if uint64(e) > math.MaxUint32 { //nolint:gosec // The exponent is guaranteed to be positive by the parser.
			return "", nil, ErrAttestationFormat.WithDetails("Invalid RSA public key size")
		}

		exp := uint32(e) //nolint:gosec // The exponent is bounds checked above.

		if tpm2Exponent(params) != exp {
			return "", nil, ErrAttestationFormat.WithDetails("Mismatch between RSAParameters in pubArea and credentialPublicKey")
		}
	default:
		return "", nil, ErrUnsupportedKey
	}

	// Concatenate authenticatorData and clientDataHash to form attToBeSigned.
	attToBeSigned := slices.Concat(att.RawAuthData, clientDataHash)

	var certInfo *tpm2.TPMSAttest

	// Validate that certInfo is valid:
	// 1/4 Verify that magic is set to TPM_GENERATED_VALUE, handled here.
	if certInfo, err = tpm2.Unmarshal[tpm2.TPMSAttest](statement.CertInfo); err != nil {
		return "", nil, err
	}

	if err = certInfo.Magic.Check(); err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails("Magic is not set to TPM_GENERATED_VALUE")
	}

	// 2/4 Verify that type is set to TPM_ST_ATTEST_CERTIFY.
	if certInfo.Type != tpm2.TPMSTAttestCertify {
		return "", nil, ErrAttestationFormat.WithDetails("Type is not set to TPM_ST_ATTEST_CERTIFY")
	}

	// 3/4 Verify that extraData is set to the hash of attToBeSigned using the hash algorithm employed in "alg".
	coseAlg := webauthncose.COSEAlgorithmIdentifier(statement.Algorithm)

	h, supported := webauthncose.HasherFromCOSEAlg(coseAlg)
	if !supported {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Unsupported COSE alg: %d", statement.Algorithm))
	}

	h.Write(attToBeSigned)

	if !bytes.Equal(certInfo.ExtraData.Buffer, h.Sum(nil)) {
		return "", nil, ErrAttestationFormat.WithDetails("ExtraData is not set to hash of attToBeSigned")
	}

	// Note that the remaining fields in the "Standard Attestation Structure"
	// [TPMv2-Part1] section 31.2, i.e., qualifiedSigner, clockInfo and firmwareVersion
	// are ignored. These fields MAY be used as an input to risk engines.
	var (
		aikCert *x509.Certificate
		raw     []byte
		ok      bool
	)

	if len(statement.X5C) == 0 {
		return "", nil, ErrAttestation.WithDetails("Error getting certificate from x5c cert chain")
	}

	// In this case:
	// Verify the sig is a valid signature over certInfo using the attestation public key in aikCert with the algorithm specified in alg.
	if raw, ok = statement.X5C[0].([]byte); !ok {
		return "", nil, ErrAttestation.WithDetails("Error getting certificate from x5c cert chain")
	}

	if aikCert, err = x509.ParseCertificate(raw); err != nil {
		return "", nil, ErrAttestationFormat.WithDetails("Error parsing certificate from ASN.1")
	}

	if sigAlg := webauthncose.SigAlgFromCOSEAlg(coseAlg); sigAlg == x509.UnknownSignatureAlgorithm {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Unsupported COSE alg: %d", statement.Algorithm))
	} else if err = certCheckSignature(aikCert, sigAlg, statement.CertInfo, statement.Signature, signature); err != nil {
		return "", nil, ErrAttestationFormat.WithDetails(fmt.Sprintf("Signature validation error: %+v", err))
	}

	// Verify that aikCert meets the requirements in §8.3.1 TPM Attestation Statement Certificate Requirements.

	// 1/6 Version MUST be set to 3.
	if aikCert.Version != 3 {
		return "", nil, ErrAttestationFormat.WithDetails("AIK certificate version must be 3")
	}

	// 2/6 Subject field MUST be set to empty.
	if aikCert.Subject.String() != "" {
		return "", nil, ErrAttestationFormat.WithDetails("AIK certificate subject must be empty")
	}

	var (
		manufacturer, model, version string
		ekuValid                     = false
		constraintsValid             = false
		eku                          []asn1.ObjectIdentifier
		constraints                  tpmBasicConstraints
		rest                         []byte
	)

	for _, ext := range aikCert.Extensions {
		switch {
		case ext.Id.Equal(oidExtensionSubjectAltName):
			if manufacturer, model, version, err = parseSANExtension(ext.Value); err != nil {
				return "", nil, err
			}
		case ext.Id.Equal(oidExtensionExtendedKeyUsage):
			if rest, err = asn1.Unmarshal(ext.Value, &eku); err != nil {
				return "", nil, ErrAttestationFormat.WithDetails("AIK certificate extended key usage malformed")
			} else if len(rest) != 0 {
				return "", nil, ErrAttestationFormat.WithDetails("AIK certificate extended key usage contains extra data")
			}

			found := false

			for _, oid := range eku {
				if oid.Equal(oidTCGKpAIKCertificate) {
					found = true
					break
				}
			}

			if !found {
				return "", nil, ErrAttestationFormat.WithDetails("AIK certificate extended key usage missing 2.23.133.8.3")
			}

			ekuValid = true
		case ext.Id.Equal(oidExtensionBasicConstraints):
			if rest, err = asn1.Unmarshal(ext.Value, &constraints); err != nil {
				return "", nil, ErrAttestationFormat.WithDetails("AIK certificate basic constraints malformed")
			} else if len(rest) != 0 {
				return "", nil, ErrAttestationFormat.WithDetails("AIK certificate basic constraints contains extra data")
			}

			constraintsValid = true
		}
	}

	// 3/6 The Subject Alternative Name extension MUST be set as defined in [TPMv2-EK-Profile] section 3.2.9.
	if manufacturer == "" || model == "" || version == "" {
		return "", nil, ErrAttestationFormat.WithDetails("Invalid SAN data in AIK certificate")
	}

	if !isValidTPMManufacturer(manufacturer) {
		return "", nil, ErrAttestationFormat.WithDetails("Invalid TPM manufacturer")
	}

	// 4/6 The Extended Key Usage extension MUST contain the "joint-iso-itu-t(2) internationalorganizations(23) 133 tcg-kp(8) tcg-kp-AIKCertificate(3)" OID.
	if !ekuValid {
		return "", nil, ErrAttestationFormat.WithDetails("AIK certificate missing EKU")
	}

	// 5/6 The Basic Constraints extension MUST have the CA component set to false. An absent extension can't have the
	// CA component set to false so it's rejected in the same way as one which asserts CA is true.
	//
	// 6/6 An Authority Information Access (AIA) extension with entry id-ad-ocsp and a CRL Distribution Point
	// extension [RFC5280] are both OPTIONAL as the status of many attestation certificates is available
	// through metadata services. See, for example, the FIDO Metadata Service.
	if !constraintsValid || constraints.IsCA {
		return "", nil, ErrAttestationFormat.WithDetails("AIK certificate basic constraints missing or CA is true")
	}

	// If aikCert contains an extension with OID 1.3.6.1.4.1.45724.1.1.4 (id-fido-gen-ce-aaguid) verify that the value
	// of this extension matches the aaguid in authenticatorData.
	var (
		aaguid []byte
		found  bool
	)

	if aaguid, _, found, err = attestationCertAAGUID(aikCert); err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails("Error unmarshalling AAGUID from certificate").WithError(err)
	} else if found && !bytes.Equal(aaguid, att.AuthData.AttData.AAGUID) {
		return "", nil, ErrInvalidAttestation.WithDetails("Certificate AAGUID does not match Auth Data certificate")
	}

	// 4/4 Verify that attested contains a TPMS_CERTIFY_INFO structure as specified in
	// [TPMv2-Part2] section 10.12.3, whose name field contains a valid Name for pubArea,
	// as computed using the algorithm in the nameAlg field of pubArea
	// using the procedure specified in [TPMv2-Part1] section 16.
	//
	// This needs to move after the x5c check as the QualifiedSigner only gets populated when it can be verified.
	if ok, err = tpm2NameMatch(certInfo, pubArea); err != nil {
		return "", nil, err
	} else if !ok {
		return "", nil, ErrAttestationFormat.WithDetails("Hash value mismatch attested and pubArea")
	}

	return string(metadata.AttCA), statement.X5C, err
}

func tpm2Exponent(params *tpm2.TPMSRSAParms) (exp uint32) {
	if params.Exponent != 0 {
		return params.Exponent
	}

	return 65537
}

func tpm2NameMatch(certInfo *tpm2.TPMSAttest, pubArea *tpm2.TPMTPublic) (match bool, err error) {
	if certInfo == nil || pubArea == nil {
		return false, nil
	}

	var (
		certifyInfo *tpm2.TPMSCertifyInfo
		name        *tpm2.TPM2BName
	)

	if certifyInfo, err = certInfo.Attested.Certify(); err != nil {
		return false, err
	}

	if name, err = tpm2.ObjectName(pubArea); err != nil {
		return false, err
	}

	// Per the WebAuthn Specification §8.3 step 5:
	//
	// Note: The remaining fields in the "Standard Attestation Structure" [TPMv2-Part1] section 31.2, i.e.,
	// qualifiedSigner, clockInfo and firmwareVersion are ignored. Depending on the properties of the aikCert key used,
	// these fields may be obfuscated. If valid, these MAY be used as an input to risk engines.
	//
	// See: https://w3c.github.io/webauthn/#sctn-tpm-attestation

	return subtle.ConstantTimeCompare(certifyInfo.Name.Buffer, name.Buffer) == 1, nil
}

type tpm2AttStatement struct {
	Version   string
	Algorithm int64
	Signature []byte
	CertInfo  []byte
	PubArea   []byte

	X5C         []any
	HasX5C      bool
	HasValidX5C bool

	HasECDAAKeyID      bool
	HasValidECDAAKeyID bool
	ECDAAKeyID         []byte
}

func newTPM2AttStatement(raw map[string]any) (statement *tpm2AttStatement, err error) {
	var ok bool

	statement = &tpm2AttStatement{}

	// Given the verification procedure inputs attStmt, authenticatorData
	// and clientDataHash, the verification procedure is as follows.

	// Verify that attStmt is valid CBOR conforming to the syntax defined
	// above and perform CBOR decoding on it to extract the contained fields.
	if statement.Version, ok = raw[stmtVersion].(string); !ok {
		return nil, ErrAttestationFormat.WithDetails("Error retrieving ver value")
	}

	if statement.Algorithm, ok = raw[stmtAlgorithm].(int64); !ok {
		return nil, ErrAttestationFormat.WithDetails("Error retrieving alg value")
	}

	if statement.Signature, ok = raw[stmtSignature].([]byte); !ok {
		return nil, ErrAttestationFormat.WithDetails("Error retrieving sig value")
	}

	if statement.CertInfo, ok = raw[stmtCertInfo].([]byte); !ok {
		return nil, ErrAttestationFormat.WithDetails("Error retrieving certInfo value")
	}

	if statement.PubArea, ok = raw[stmtPubArea].([]byte); !ok {
		return nil, ErrAttestationFormat.WithDetails("Error retrieving pubArea value")
	}

	var rawX5C, rawECDAAKeyID any

	rawX5C, statement.HasX5C = raw[stmtX5C]
	statement.X5C, statement.HasValidX5C = rawX5C.([]any)

	rawECDAAKeyID, statement.HasECDAAKeyID = raw[stmtECDAAKID]
	statement.ECDAAKeyID, statement.HasValidECDAAKeyID = rawECDAAKeyID.([]byte)

	return statement, nil
}

// forEachSAN loops through the TPM SAN extension.
//
// RFC 5280, 4.2.1.6
// SubjectAltName ::= GeneralNames
//
// GeneralNames ::= SEQUENCE SIZE (1..MAX) OF GeneralName
//
//	GeneralName ::= CHOICE {
//	     otherName                       [0]     OtherName,
//	     rfc822Name                      [1]     IA5String,
//	     dNSName                         [2]     IA5String,
//	     x400Address                     [3]     ORAddress,
//	     directoryName                   [4]     Name,
//	     ediPartyName                    [5]     EDIPartyName,
//	     uniformResourceIdentifier       [6]     IA5String,
//	     iPAddress                       [7]     OCTET STRING,
//	     registeredID                    [8]     OBJECT IDENTIFIER }
func forEachSAN(extension []byte, callback func(tag int, data []byte) error) error {
	var seq asn1.RawValue

	rest, err := asn1.Unmarshal(extension, &seq)
	if err != nil {
		return err
	} else if len(rest) != 0 {
		return errors.New("x509: trailing data after X.509 extension")
	}

	if !seq.IsCompound || seq.Tag != 16 || seq.Class != 0 {
		return asn1.StructuralError{Msg: "bad SAN sequence"}
	}

	rest = seq.Bytes

	for len(rest) > 0 {
		var v asn1.RawValue

		rest, err = asn1.Unmarshal(rest, &v)
		if err != nil {
			return err
		}

		if err = callback(v.Tag, v.Bytes); err != nil {
			return err
		}
	}

	return nil
}

const (
	nameTypeDN = 4
)

func parseSANExtension(value []byte) (manufacturer string, model string, version string, err error) {
	err = forEachSAN(value, func(tag int, data []byte) error {
		if tag == nameTypeDN {
			tpmDeviceAttributes := pkix.RDNSequence{}

			if _, err = asn1.Unmarshal(data, &tpmDeviceAttributes); err != nil {
				return err
			}

			for _, rdn := range tpmDeviceAttributes {
				if len(rdn) == 0 {
					continue
				}

				for _, atv := range rdn {
					value, ok := atv.Value.(string)
					if !ok {
						continue
					}

					if atv.Type.Equal(oidTCGAtTpmManufacturer) {
						manufacturer = strings.TrimPrefix(value, "id:")
					}

					if atv.Type.Equal(oidTCGAtTpmModel) {
						model = value
					}

					if atv.Type.Equal(oidTCGAtTPMVersion) {
						version = strings.TrimPrefix(value, "id:")
					}
				}
			}
		}

		return nil
	})

	return
}

type tpmManufacturer struct {
	id   string
	name string
	code string
}

// tpmParseAIKAttCA prepares an Attestation Identity Key certificate and its parents for chain verification against the
// Metadata Service.
//
// The only adjustment required is clearing the critical Subject Alternative Name, as crypto/x509 has no verification
// option which accepts a critical extension it doesn't itself parse. The Extended Key Usages are left intact as the
// verifier requests x509.ExtKeyUsageAny, which admits the TCG and Microsoft usages. §8.3.1 requires the attestation
// certificate carry the AIK Extended Key Usage, which the TPM attestation handler enforces against the same
// certificate.
func tpmParseAIKAttCA(x5c *x509.Certificate, x5cis []*x509.Certificate) (leaf *x509.Certificate, parents []*x509.Certificate, protoErr *Error) {
	if leaf, protoErr = tpmParseSANExtension(x5c); protoErr != nil {
		return nil, nil, protoErr
	}

	return leaf, x5cis, nil
}

func tpmParseSANExtension(attestation *x509.Certificate) (out *x509.Certificate, protoErr *Error) {
	var (
		manufacturer, model, version string
		err                          error
	)

	for _, ext := range attestation.Extensions {
		if ext.Id.Equal(oidExtensionSubjectAltName) {
			if manufacturer, model, version, err = parseSANExtension(ext.Value); err != nil {
				return nil, ErrInvalidAttestation.WithDetails("Authenticator with invalid Authenticator Identity Key SAN data encountered during attestation validation.").WithInfo(fmt.Sprintf("Error occurred parsing SAN extension: %s", err.Error())).WithError(err)
			}
		}
	}

	if manufacturer == "" || model == "" || version == "" {
		return nil, ErrAttestationFormat.WithDetails("Invalid SAN data in AIK certificate.")
	}

	var unhandled []asn1.ObjectIdentifier

	for _, uce := range attestation.UnhandledCriticalExtensions {
		if uce.Equal(oidExtensionSubjectAltName) {
			continue
		}

		unhandled = append(unhandled, uce)
	}

	out = new(x509.Certificate)
	*out = *attestation
	out.UnhandledCriticalExtensions = unhandled

	return out, nil
}

type tpmBasicConstraints struct {
	IsCA       bool `asn1:"optional"`
	MaxPathLen int  `asn1:"optional,default:-1"`
}

func init() {
	RegisterAttestationFormat(AttestationFormatTPM, attestationFormatValidationHandlerTPM)
}
