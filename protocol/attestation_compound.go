package protocol

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"github.com/google/uuid"

	"github.com/go-webauthn/webauthn/metadata"
)

func init() {
	RegisterAttestationFormat(AttestationFormatCompound, attestationFormatValidationHandlerCompound)
}

// attestationFormatValidationHandlerCompound is the handler for the Compound Attestation Statement Format.
//
// The syntax of a Compound Attestation statement is defined by the following CDDL:
//
// $$attStmtType //= (
//
//	    fmt: "compound",
//	    attStmt: [2* nonCompoundAttStmt]
//	)
//
// nonCompoundAttStmt = { $$attStmtType } .within { fmt: text .ne "compound", * any => any }
//
// §8.9 leaves the handling of a sub-statement which fails verification, and the number which must succeed, to Relying
// Party policy. The scope carries that decision and the zero value selects the strictest behavior available: every
// sub-statement must verify, and the first failure rejects the attestation. See [CompoundSubStatementScope].
//
// Specification: §8.9. Compound Attestation Statement Forma
//
// See: https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation
func attestationFormatValidationHandlerCompound(att AttestationObject, clientDataHash []byte, mds metadata.Provider, policy AttestationPolicy, signature SignaturePolicy) (attestationType string, x5cs []any, err error) {
	var (
		aaguid   uuid.UUID
		ok       bool
		attStmts []NonCompoundAttestationObject
	)

	if len(att.AuthData.AttData.AAGUID) != 0 {
		if aaguid, err = uuid.FromBytes(att.AuthData.AttData.AAGUID); err != nil {
			return "", nil, ErrInvalidAttestation.WithInfo("Error occurred parsing AAGUID during attestation validation").WithDetails(err.Error()).WithError(err)
		}
	}

	// The sub-statements are decoded from the attStmt array by [AttestationObject.UnmarshalCBOR], which is where the
	// §8.9 shape is enforced; an attStmt which is absent, or which is not an array, leaves this empty.
	if len(att.SubStatements) < 2 {
		return "", nil, ErrInvalidAttestation.WithDetails("Compound statement attStmt isn't an array with at least two other statements")
	}

	for _, attStmt := range att.SubStatements {
		switch AttestationFormat(attStmt.Format) {
		case AttestationFormatCompound:
			return "", nil, ErrInvalidAttestation.WithDetails("Compound sub-statement has a format of compound which is not allowed")
		case "":
			return "", nil, ErrInvalidAttestation.WithDetails("Compound sub-statement has an empty format which is not allowed")
		default:
			if attStmt.AttStatement == nil {
				return "", nil, ErrInvalidAttestation.WithDetails("Compound sub-statement does not have an attestation statement")
			}

			if _, ok = attestationRegistry[AttestationFormat(attStmt.Format)]; !ok {
				return "", nil, ErrAttestationFormat.WithInfo(fmt.Sprintf("Attestation sub-statement format %s is unsupported", attStmt.Format))
			}

			attStmts = append(attStmts, attStmt)
		}
	}

	// The trust paths are not conveyed to the caller. Each is validated against the Metadata Service by the
	// verification below alongside the format and attestation type it belongs to, which a single chain can't describe
	// for more than one sub-statement, and the paths of independent sub-statements joined together describe no real
	// chain.
	if policy.Compound.SubStatementScope.any() {
		return compoundVerifySubStatementsAny(att, attStmts, clientDataHash, mds, policy, signature, aaguid)
	}

	return compoundVerifySubStatementsAll(att, attStmts, clientDataHash, mds, policy, signature, aaguid)
}

// compoundVerifySubStatementsAll verifies every sub-statement, rejecting the attestation on the first which fails.
//
// This is the behavior of [CompoundSubStatementScopeAll].
func compoundVerifySubStatementsAll(att AttestationObject, attStmts []NonCompoundAttestationObject, clientDataHash []byte, mds metadata.Provider, policy AttestationPolicy, signature SignaturePolicy, aaguid uuid.UUID) (attestationType string, x5cs []any, err error) {
	for i, attStmt := range attStmts {
		var subAttType string

		if subAttType, err = compoundVerifySubStatement(att, attStmt, clientDataHash, mds, policy, signature, aaguid); err != nil {
			return "", nil, err
		}

		// Every sub-statement attests the same credential, so the type conveyed by the first describes an attestation
		// which was obtained and is the value recorded against the credential.
		if i == 0 {
			attestationType = subAttType
		}
	}

	return attestationType, nil, nil
}

// compoundVerifySubStatementsAny verifies sub-statements until one of them succeeds, rejecting the attestation only
// when none can be verified. The sub-statements after the first success are not verified as the scope is satisfied
// by it, and the failures of the sub-statements before it are conveyed together so the reason the accepted one was
// reached is not lost.
//
// This is the behavior of [CompoundSubStatementScopeAny].
func compoundVerifySubStatementsAny(att AttestationObject, attStmts []NonCompoundAttestationObject, clientDataHash []byte, mds metadata.Provider, policy AttestationPolicy, signature SignaturePolicy, aaguid uuid.UUID) (attestationType string, x5cs []any, err error) {
	var (
		errs    = make([]error, 0, len(attStmts))
		reasons = make([]string, 0, len(attStmts))
	)

	for _, attStmt := range attStmts {
		var subAttType string

		if subAttType, err = compoundVerifySubStatement(att, attStmt, clientDataHash, mds, policy, signature, aaguid); err != nil {
			errs = append(errs, err)
			reasons = append(reasons, fmt.Sprintf("%s: %s", attStmt.Format, compoundSubStatementFailureReason(err)))

			continue
		}

		// The sub-statement which was verified is the one which describes an attestation which was obtained, so its
		// type is the value recorded against the credential rather than that of a sub-statement which failed.
		return subAttType, nil, nil
	}

	return "", nil, ErrInvalidAttestation.
		WithDetails(fmt.Sprintf("Compound statement does not contain any sub-statement which could be verified (%s)", strings.Join(reasons, "; "))).
		WithError(errors.Join(errs...))
}

// compoundSubStatementFailureReason describes the failure of a sub-statement for the aggregate error of the any
// scope. The details of an [Error] are preferred as they name the specific failure, falling back to the debug
// information and then the type so that a failed sub-statement is never described by an empty string.
func compoundSubStatementFailureReason(err error) string {
	var e *Error

	if !errors.As(err, &e) {
		return err.Error()
	}

	switch {
	case e.Details != "":
		return e.Details
	case e.DevInfo != "":
		return e.DevInfo
	default:
		return e.Type
	}
}

// compoundVerifySubStatement performs the verification procedure of a single sub-statement and validates the trust
// path it produces against the Metadata Service. A sub-statement is verified in full or not at all, so a scope which
// tolerates a failure treats a sub-statement whose trust path the Metadata Service rejects the same as one whose
// verification procedure fails.
func compoundVerifySubStatement(att AttestationObject, attStmt NonCompoundAttestationObject, clientDataHash []byte, mds metadata.Provider, policy AttestationPolicy, signature SignaturePolicy, aaguid uuid.UUID) (attestationType string, err error) {
	object := AttestationObject{
		Format:       attStmt.Format,
		AttStatement: attStmt.AttStatement,
		AuthData:     att.AuthData,
		RawAuthData:  att.RawAuthData,
	}

	var cx5cs []any

	if attestationType, cx5cs, err = attestationRegistry[AttestationFormat(object.Format)](object, clientDataHash, mds, policy, signature); err != nil {
		return "", err
	}

	if mds == nil {
		return attestationType, nil
	}

	if e := ValidateMetadata(context.Background(), mds, aaguid, attestationType, object.Format, cx5cs); e != nil {
		return "", ErrInvalidAttestation.WithInfo(fmt.Sprintf("Error occurred validating metadata during attestation validation: %+v", e)).WithDetails(e.DevInfo).WithError(e)
	}

	return attestationType, nil
}
