package protocol

import (
	"bytes"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

// attestationFormatValidationHandlerAndroidKey is the handler for the Android Key Attestation Statement Format.
//
// An Android key attestation statement consists simply of the Android attestation statement, which is a series of DER
// encoded X.509 certificates. See the Android developer documentation. Its syntax is defined as follows:
//
// $$attStmtType //= (
//
//	    fmt: "android-key",
//	    attStmt: androidStmtFormat
//	)
//
//	androidStmtFormat = {
//	                      alg: COSEAlgorithmIdentifier,
//	                      sig: bytes,
//	                      x5c: [ credCert: bytes, * (caCert: bytes) ]
//	                    }
//
// Specification: §8.4. Android Key Attestation Statement Format
//
// See: https://www.w3.org/TR/webauthn/#sctn-android-key-attestation
//
//nolint:gocyclo
func attestationFormatValidationHandlerAndroidKey(att AttestationObject, clientDataHash []byte, _ metadata.Provider, policy AttestationPolicy, signature SignaturePolicy) (attestationType string, x5cs []any, err error) {
	var (
		alg int64
		sig []byte
		ok  bool
	)

	// Given the verification procedure inputs attStmt, authenticatorData and clientDataHash, the verification procedure is as follows:
	// §8.4.1. Verify that attStmt is valid CBOR conforming to the syntax defined above and perform CBOR decoding on it to extract
	// the contained fields.
	// Get the alg value - A COSEAlgorithmIdentifier containing the identifier of the algorithm
	// used to generate the attestation signature.
	if alg, ok = att.AttStatement[stmtAlgorithm].(int64); !ok {
		return "", nil, ErrAttestationFormat.WithDetails("Error retrieving alg value")
	}

	// Get the sig value - A byte string containing the attestation signature.
	if sig, ok = att.AttStatement[stmtSignature].([]byte); !ok {
		return "", nil, ErrAttestationFormat.WithDetails("Error retrieving sig value")
	}

	// §8.4.2. Verify that sig is a valid signature over the concatenation of authenticatorData and clientDataHash
	// using the public key in the first certificate in x5c with the algorithm specified in alg.
	var (
		x5c   []any
		certs []*x509.Certificate
	)

	if x5c, certs, err = attStatementParseX5CS(att.AttStatement, stmtX5C); err != nil {
		return "", nil, err
	}

	if len(certs) == 0 {
		return "", nil, ErrInvalidAttestation.WithDetails("No certificates in x5c")
	}

	credCert := certs[0]

	if _, err = attStatementCertChainVerify(certs, attAndroidKeyHardwareRootsCertPool, true, time.Now().Add(time.Hour*8760).UTC()); err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails("Error validating x5c cert chain").WithError(err)
	}

	signatureData := slices.Concat(att.RawAuthData, clientDataHash)

	if sigAlg := webauthncose.SigAlgFromCOSEAlg(webauthncose.COSEAlgorithmIdentifier(alg)); sigAlg == x509.UnknownSignatureAlgorithm {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Unsupported COSE alg: %d", alg))
	} else if err = certCheckSignature(credCert, sigAlg, signatureData, sig, signature); err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Signature validation error: %+v", err)).WithError(err)
	}

	// Verify that the public key in the first certificate in x5c matches the credentialPublicKey in the attestedCredentialData in authenticatorData.
	var credentialPublicKey any

	if credentialPublicKey, err = verifyAttestationPublicKeyMatch(att, credCert); err != nil {
		return "", nil, err
	}

	// The signature was verified above with the certificate public key and the algorithm of the attestation
	// statement. Repeating it with the credential public key additionally requires the two to agree on the algorithm,
	// as each selects the digest from the algorithm it carries.
	var valid bool

	if valid, err = keyVerifySignature(credentialPublicKey, signatureData, sig, signature); err != nil {
		return "", nil, ErrInvalidAttestation.WithDetails(fmt.Sprintf("Error verifying the signature with the credential public key: %+v", err)).WithError(err)
	} else if !valid {
		return "", nil, ErrInvalidAttestation.WithDetails("Signature is not valid for the credential public key")
	}

	// §8.4.3. Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
	// attCert.Extensions.
	// As noted in §8.4.1 (https://www.w3.org/TR/webauthn/#key-attstn-cert-requirements) the Android Key Attestation
	// certificate's android key attestation certificate extension data is identified by the OID
	// "1.3.6.1.4.1.11129.2.1.17".
	var attExtBytes []byte

	for _, ext := range credCert.Extensions {
		if ext.Id.Equal(oidExtensionAndroidKeystore) {
			attExtBytes = ext.Value
		}
	}

	if len(attExtBytes) == 0 {
		return "", nil, ErrAttestationFormat.WithDetails("Attestation certificate extensions missing 1.3.6.1.4.1.11129.2.1.17")
	}

	decoded := androidkeyDescription{}

	if _, err = asn1.Unmarshal(attExtBytes, &decoded); err != nil {
		return "", nil, ErrAttestationFormat.WithDetails("Unable to parse Android key attestation certificate extensions").WithError(err)
	}

	// The decode above silently abandons the remaining fields of an authorization list on meeting an element it can't
	// model, so the elements actually present are checked against the raw extension before any of it is relied upon.
	raw := androidkeyDescriptionRaw{}

	if _, err = asn1.Unmarshal(attExtBytes, &raw); err != nil {
		return "", nil, ErrAttestationFormat.WithDetails("Unable to parse Android key attestation certificate extensions").WithError(err)
	}

	if protoErr := androidKeyVerifyAuthorizationListTags(&raw); protoErr != nil {
		return "", nil, protoErr
	}

	// Verify that the attestationChallenge field in the attestation certificate extension data is identical to clientDataHash.
	if !bytes.Equal(decoded.AttestationChallenge, clientDataHash) {
		return "", nil, ErrAttestationFormat.WithDetails("Attestation challenge not equal to clientDataHash")
	}

	if protoErr := androidKeyValidateAuthorizationLists(&decoded, policy.AndroidKey.AuthorizationScope); protoErr != nil {
		return "", nil, protoErr
	}

	return string(metadata.BasicFull), x5c, err
}

// androidKeyValidateAuthorizationLists performs the §8.4 verification steps which apply to the authorization lists
// of the Android key attestation certificate extension.
//
// The scope selects the lists the origin and purpose requirements are evaluated against, which §8.4 leaves to the
// Relying Party. See [AndroidKeyAuthorizationScope].
func androidKeyValidateAuthorizationLists(decoded *androidkeyDescription, scope AndroidKeyAuthorizationScope) *Error {
	// The AuthorizationList.allApplications field is not present on either authorization list (softwareEnforced nor teeEnforced), since PublicKeyCredential MUST be scoped to the RP ID.
	//
	// This requirement precedes the sentence which introduces the Relying Party's choice of scope, so it applies to
	// both lists regardless of the scope in effect.
	if len(decoded.SoftwareEnforced.AllApplications.FullBytes) != 0 || len(decoded.TeeEnforced.AllApplications.FullBytes) != 0 {
		return ErrAttestationFormat.WithDetails("Attestation certificate extensions contains all applications field")
	}

	// For the following, use only the teeEnforced authorization list if the RP wants to accept only keys from a trusted execution environment, otherwise use the union of teeEnforced and softwareEnforced.
	union := scope.union()

	// The value in the AuthorizationList.origin field is equal to KM_ORIGIN_GENERATED (which == 0).
	var (
		originTee, originSoftware   int
		presentTee, presentSoftware bool
		err                         error
	)

	if originTee, presentTee, err = authorizationListOrigin(&decoded.TeeEnforced); err != nil {
		return ErrAttestationFormat.WithDetails("Unable to parse the origin of the teeEnforced authorization list").WithError(err)
	}

	// The softwareEnforced list is only parsed when the scope consults it, so a malformed origin there cannot fail
	// an attestation the teeEnforced scope would otherwise accept on the teeEnforced list alone.
	if union {
		if originSoftware, presentSoftware, err = authorizationListOrigin(&decoded.SoftwareEnforced); err != nil {
			return ErrAttestationFormat.WithDetails("Unable to parse the origin of the softwareEnforced authorization list").WithError(err)
		}
	}

	// An absent origin satisfies nothing as there is no value to compare against, which mirrors the purpose check
	// below.
	generated := presentTee && originTee == KM_ORIGIN_GENERATED

	if union && !generated {
		generated = presentSoftware && originSoftware == KM_ORIGIN_GENERATED
	}

	if !generated {
		return ErrAttestationFormat.WithDetails(fmt.Sprintf("Attestation certificate extensions contains %s with origin not equal KM_ORIGIN_GENERATED", androidKeyScopeDescription(union)))
	}

	// The value in the AuthorizationList.purpose field is equal to KM_PURPOSE_SIGN (which == 2).
	sign := contains(decoded.TeeEnforced.Purpose, KM_PURPOSE_SIGN)

	if union && !sign {
		sign = contains(decoded.SoftwareEnforced.Purpose, KM_PURPOSE_SIGN)
	}

	if !sign {
		return ErrAttestationFormat.WithDetails(fmt.Sprintf("Attestation certificate extensions contains %s with purpose not equal KM_PURPOSE_SIGN", androidKeyScopeDescription(union)))
	}

	return nil
}

// androidKeyScopeDescription names the authorization lists the §8.4 origin and purpose requirements were evaluated
// against so that a failure identifies the scope in effect. The union wording is unqualified as it matches the
// specification's own phrasing and preserves the error text of the union scope.
func androidKeyScopeDescription(union bool) string {
	if union {
		return "authorization list"
	}

	return "teeEnforced authorization list"
}

// authorizationListOrigin returns the origin of an authorization list and reports whether the field was present. The
// value is decoded from the raw element because encoding/asn1 leaves an absent optional integer at its zero value,
// which is indistinguishable from a present origin of KM_ORIGIN_GENERATED.
func authorizationListOrigin(list *androidkeyAuthorizationList) (origin int, present bool, err error) {
	// An explicit tag which is present always carries a child as encoding/asn1 rejects one which doesn't while
	// decoding the key description, so an empty raw value means the field was absent rather than empty.
	if len(list.Origin.FullBytes) == 0 {
		return 0, false, nil
	}

	var rest []byte

	if rest, err = asn1.Unmarshal(list.Origin.Bytes, &origin); err != nil {
		return 0, false, err
	}

	if len(rest) != 0 {
		return 0, false, fmt.Errorf("origin has %d bytes of trailing data", len(rest))
	}

	return origin, true, nil
}

func contains(s []int, e int) bool {
	for _, a := range s {
		if a == e {
			return true
		}
	}

	return false
}

// authorizationListTags contains every context specific tag number modelled by [authorizationList]. It's derived from
// the struct definition so that declaring a field is the only step needed to support a tag, and the two can't drift.
var authorizationListTags = func() (tags map[int]bool) {
	t := reflect.TypeOf(androidkeyAuthorizationList{})

	tags = make(map[int]bool, t.NumField())

	for i := range t.NumField() {
		field := t.Field(i)

		for _, option := range strings.Split(field.Tag.Get("asn1"), ",") {
			if !strings.HasPrefix(option, "tag:") {
				continue
			}

			tag, err := strconv.Atoi(strings.TrimPrefix(option, "tag:"))
			if err != nil {
				panic(fmt.Sprintf("protocol: authorizationList field %s has a malformed asn1 tag: %v", field.Name, err))
			}

			tags[tag] = true
		}
	}

	return tags
}()

// authorizationListValidatedTags contains the tags of the authorization list fields which the §8.4 verification steps
// consult. An element the struct can't model only matters when it displaces one of these.
var authorizationListValidatedTags = []int{
	1,   // purpose.
	600, // allApplications.
	702, // origin.
}

// androidKeyVerifyAuthorizationListTags rejects an attestation whose authorization lists carry an element that
// [authorizationList] can't model and which precedes a field the verification procedure depends on.
//
// An unmodelled tag otherwise defeats the §8.4 requirement that allApplications is absent, as the element is dropped
// along with every field declared after it. That requirement is checked against both lists in every scope, not only
// when the union scope draws on softwareEnforced for the origin and purpose checks, so an unmodelled tag in either
// list needs the same protection regardless of which scope the Relying Party has selected. A list which can't be
// modelled in full is rejected explicitly rather than silently truncated.
func androidKeyVerifyAuthorizationListTags(raw *androidkeyDescriptionRaw) *Error {
	for _, list := range []struct {
		name string
		raw  asn1.RawValue
	}{
		{"teeEnforced", raw.TeeEnforced},
		{"softwareEnforced", raw.SoftwareEnforced},
	} {
		if err := authorizationListVerifyTags(list.raw); err != nil {
			return ErrAttestationFormat.WithDetails(fmt.Sprintf("Unable to validate the %s authorization list", list.name)).WithInfo(err.Error()).WithError(err)
		}
	}

	return nil
}

// authorizationListVerifyTags reports an error when an element of the raw authorization list isn't modelled by
// [authorizationList] and is positioned before an element the verification procedure consults. Anything after the last
// consulted element can't influence the outcome as decoding reached them all, which keeps a tag appended to a later
// revision of the schema from rejecting an otherwise sound attestation.
func authorizationListVerifyTags(raw asn1.RawValue) (err error) {
	if raw.Class != asn1.ClassUniversal || raw.Tag != asn1.TagSequence || !raw.IsCompound {
		return errors.New("authorization list is not a sequence")
	}

	var tags []int

	rest := raw.Bytes

	for len(rest) > 0 {
		var element asn1.RawValue

		if rest, err = asn1.Unmarshal(rest, &element); err != nil {
			return err
		}

		if element.Class != asn1.ClassContextSpecific {
			return fmt.Errorf("element %d has class %d where a context specific class was expected", len(tags), element.Class)
		}

		tags = append(tags, element.Tag)
	}

	last := -1

	for i, tag := range tags {
		if contains(authorizationListValidatedTags, tag) {
			last = i
		}
	}

	for i, tag := range tags[:last+1] {
		if authorizationListTags[tag] {
			continue
		}

		return fmt.Errorf("element %d has tag [%d] which is not supported and precedes a field required by the verification procedure", i, tag)
	}

	return nil
}

var (
	attAndroidKeyHardwareRootsCertPool *x509.CertPool
)

func init() {
	RegisterAttestationFormat(AttestationFormatAndroidKey, attestationFormatValidationHandlerAndroidKey)
}
