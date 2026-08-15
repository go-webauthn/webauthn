package protocol

import (
	"bytes"
	"crypto/sha256"
	"maps"
	"testing"

	cbor "github.com/fxamacker/cbor/v2"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

// TestCompoundAttestation_SpecShapeDecodes asserts that a compound attestation object using the shape defined in §8.9,
// where attStmt is an array of sub-statements rather than a map, survives CBOR decoding and exposes its
// sub-statements.
//
// Specification: §8.9. Compound Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation)
func TestCompoundAttestation_SpecShapeDecodes(t *testing.T) {
	rawAuthData, packed, _ := compoundE2EPackedSelfVector(t)

	data := compoundE2EEncode(t, rawAuthData, packed, packed)

	var att AttestationObject

	require.NoError(t, webauthncbor.Unmarshal(data, &att))

	assert.Equal(t, string(AttestationFormatCompound), att.Format)
	assert.Equal(t, rawAuthData, att.RawAuthData)

	require.Len(t, att.SubStatements, 2)

	for i, sub := range att.SubStatements {
		assert.Equal(t, string(AttestationFormatPacked), sub.Format, "sub-statement %d", i)
		assert.Equal(t, packed, sub.AttStatement, "sub-statement %d", i)
	}
}

// TestCompoundAttestation_SpecShapeVerifies drives a §8.9 conformant compound attestation object through the real
// registration path: the response parser, then the attestation verification procedure. Both sub-statements are the
// §16.3 packed self attestation of the shared authenticator data, so both verify against the credential public key
// that authenticator data carries.
//
// Specification: §8.9. Compound Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation)
//
// Specification: §16.3. ES256 Credential with Self Attestation (https://www.w3.org/TR/webauthn-3/#sctn-test-vectors-packed-self-es256)
func TestCompoundAttestation_SpecShapeVerifies(t *testing.T) {
	rawAuthData, packed, clientDataJSON := compoundE2EPackedSelfVector(t)

	response := AuthenticatorAttestationResponse{
		AuthenticatorResponse: AuthenticatorResponse{ClientDataJSON: clientDataJSON},
		AttestationObject:     compoundE2EEncode(t, rawAuthData, packed, packed),
	}

	parsed, err := response.Parse()
	require.NoError(t, err)

	require.Len(t, parsed.AttestationObject.SubStatements, 2)

	sum := sha256.Sum256(clientDataJSON)

	require.NoError(t, parsed.AttestationObject.VerifyAttestation(sum[:], nil, AttestationPolicy{}, SignaturePolicy{}))

	assert.Equal(t, string(metadata.BasicSurrogate), parsed.AttestationObject.Type)
}

// TestCompoundAttestation_SpecShapeRejectsUnverifiableSubStatement asserts the default (all) scope still rejects a
// compound attestation when one of its sub-statements does not verify, now that the statement actually reaches the
// verification procedure.
func TestCompoundAttestation_SpecShapeRejectsUnverifiableSubStatement(t *testing.T) {
	rawAuthData, packed, clientDataJSON := compoundE2EPackedSelfVector(t)

	tampered := maps.Clone(packed)

	signature := bytes.Clone(packed[stmtSignature].([]byte))
	signature[len(signature)-1] ^= 0xff
	tampered[stmtSignature] = signature

	var att AttestationObject

	require.NoError(t, webauthncbor.Unmarshal(compoundE2EEncode(t, rawAuthData, packed, tampered), &att))

	sum := sha256.Sum256(clientDataJSON)

	require.Error(t, att.VerifyAttestation(sum[:], nil, AttestationPolicy{}, SignaturePolicy{}))
}

// TestCompoundAttestation_SpecShapeRejectsMalformedAttStmt asserts the decoder rejects a compound attStmt which is
// not the array of sub-statement maps §8.9 defines. These are the shapes the verification handler used to be
// responsible for and which now cannot reach it.
func TestCompoundAttestation_SpecShapeRejectsMalformedAttStmt(t *testing.T) {
	rawAuthData, _, _ := compoundE2EPackedSelfVector(t)

	testCases := []struct {
		name    string
		attStmt any
	}{
		{name: "ShouldRejectAttStmtNotAnArray", attStmt: "nope"},
		{name: "ShouldRejectAttStmtAsAMap", attStmt: map[string]any{stmtAttStmt: []any{}}},
		{name: "ShouldRejectAttStmtContainingNonObject", attStmt: []any{123, 456}},
		{name: "ShouldRejectAttStmtContainingByteString", attStmt: []any{[]byte{0x01}, []byte{0x02}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := cbor.Marshal(map[string]any{
				stmtAuthData: rawAuthData,
				stmtFmt:      string(AttestationFormatCompound),
				stmtAttStmt:  tc.attStmt,
			})
			require.NoError(t, err)

			var att AttestationObject

			require.Error(t, webauthncbor.Unmarshal(data, &att))
		})
	}
}

// TestCompoundAttestation_SpecShapeRejectsArrayForNonCompoundFormat asserts the array shape belongs to the compound
// format alone: a format which encodes its attestation statement as a map does not silently accept an array.
func TestCompoundAttestation_SpecShapeRejectsArrayForNonCompoundFormat(t *testing.T) {
	rawAuthData, _, _ := compoundE2EPackedSelfVector(t)

	data, err := cbor.Marshal(map[string]any{
		stmtAuthData: rawAuthData,
		stmtFmt:      string(AttestationFormatPacked),
		stmtAttStmt:  []any{map[string]any{stmtFmt: string(AttestationFormatPacked)}},
	})
	require.NoError(t, err)

	var att AttestationObject

	require.Error(t, webauthncbor.Unmarshal(data, &att))
}

func TestCompoundAttestation_NestingLimitAdmitsCertificateChain(t *testing.T) {
	rawAuthData, _, _ := compoundE2EPackedSelfVector(t)

	chained := map[string]any{
		stmtAlgorithm: int64(-7),
		stmtSignature: []byte{0x01},
		stmtX5C:       []any{[]byte{0x02}},
	}

	var att AttestationObject

	require.NoError(t, webauthncbor.Unmarshal(compoundE2EEncode(t, rawAuthData, chained, chained), &att))

	require.Len(t, att.SubStatements, 2)

	for i, sub := range att.SubStatements {
		assert.Equal(t, []any{[]byte{0x02}}, sub.AttStatement[stmtX5C], "sub-statement %d", i)
	}
}

func TestCompoundAttestation_NestingLimitStillBounded(t *testing.T) {
	var value any = "leaf"

	for range 6 {
		value = map[string]any{"a": value}
	}

	data, err := cbor.Marshal(value)
	require.NoError(t, err)

	var out any

	require.ErrorContains(t, webauthncbor.Unmarshal(data, &out), "max nested level")
}

func TestAttestationObjectUnmarshalCBORRejectsMalformedObject(t *testing.T) {
	rawAuthData, _, _ := compoundE2EPackedSelfVector(t)

	deep := any(map[string]any{stmtAttStmt: []any{map[string]any{stmtAttStmt: map[string]any{stmtX5C: []any{[]byte{0x01}}}}}})

	testCases := []struct {
		name  string
		value any
	}{
		{name: "ShouldRejectTopLevelArray", value: []any{stmtFmt, string(AttestationFormatNone)}},
		{name: "ShouldRejectTopLevelByteString", value: []byte{0x01, 0x02}},
		{name: "ShouldRejectFormatOfTheWrongType", value: map[string]any{stmtAuthData: rawAuthData, stmtFmt: int64(7)}},
		{name: "ShouldRejectAuthDataOfTheWrongType", value: map[string]any{stmtAuthData: "not bytes", stmtFmt: string(AttestationFormatNone)}},
		{name: "ShouldRejectObjectExceedingTheNestingLimit", value: map[string]any{stmtAuthData: rawAuthData, stmtFmt: string(AttestationFormatCompound), stmtAttStmt: []any{deep, deep}}},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			data, err := cbor.Marshal(tc.value)
			require.NoError(t, err)

			var att AttestationObject

			require.Error(t, webauthncbor.Unmarshal(data, &att))
		})
	}
}

func TestAttestationObjectUnmarshalCBORReusedReceiver(t *testing.T) {
	rawAuthData, packed, _ := compoundE2EPackedSelfVector(t)

	var att AttestationObject

	require.NoError(t, webauthncbor.Unmarshal(compoundE2EEncode(t, rawAuthData, packed, packed), &att))
	require.Len(t, att.SubStatements, 2)

	att.Type = "basic_surrogate"
	att.AuthData = AuthenticatorData{Counter: 42}

	require.NoError(t, webauthncbor.Unmarshal(reuseE2EEncode(t, rawAuthData, string(AttestationFormatPacked), packed), &att))

	assert.Equal(t, string(AttestationFormatPacked), att.Format)
	assert.Empty(t, att.SubStatements, "sub-statements of the compound object survived into a packed object")
	assert.Equal(t, packed, att.AttStatement)
	assert.Empty(t, att.Type, "attestation type of the previous object survived")
	assert.Zero(t, att.AuthData, "authenticator data of the previous object survived")

	sparse := map[string]any{stmtAlgorithm: int64(-257)}

	require.NoError(t, webauthncbor.Unmarshal(reuseE2EEncode(t, rawAuthData, string(AttestationFormatPacked), sparse), &att))
	assert.Equal(t, sparse, att.AttStatement, "members of the previous attestation statement were merged into this one")

	// §8.7 gives the none format an empty map as its entire attestation statement, which is the shape the §16.2 test
	// vector carries, so the statement member is present and the decoder takes its ordinary path. Decoding it over a
	// populated receiver must not leave the previous statement's members behind.
	require.NoError(t, webauthncbor.Unmarshal(reuseE2EEncode(t, rawAuthData, string(AttestationFormatNone), map[string]any{}), &att))

	assert.Equal(t, string(AttestationFormatNone), att.Format)
	assert.Empty(t, att.AttStatement, "attestation statement survived into a none attestation carrying an empty one")
	assert.Empty(t, att.SubStatements)

	// An object which omits the statement member altogether leaves the decoder early instead, so it has to be
	// asserted separately and against an equally populated receiver.
	require.NoError(t, webauthncbor.Unmarshal(reuseE2EEncode(t, rawAuthData, string(AttestationFormatPacked), sparse), &att))
	require.Equal(t, sparse, att.AttStatement)

	require.NoError(t, webauthncbor.Unmarshal(reuseE2EEncode(t, rawAuthData, string(AttestationFormatNone), nil), &att))

	assert.Equal(t, string(AttestationFormatNone), att.Format)
	assert.Empty(t, att.AttStatement, "attestation statement survived into an object which carries none")
	assert.Empty(t, att.SubStatements)
}

const stmtAuthData = "authData"

func compoundE2EPackedSelfVector(t *testing.T) (rawAuthData []byte, packed map[string]any, clientDataJSON []byte) {
	t.Helper()

	const (
		attestationObjectHex = "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2"
		clientDataJSONHex    = "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d"
	)

	var att AttestationObject

	require.NoError(t, webauthncbor.Unmarshal(specTestDecodeHex(t, attestationObjectHex), &att))
	require.Equal(t, string(AttestationFormatPacked), att.Format)
	require.NotEmpty(t, att.AttStatement)

	return att.RawAuthData, att.AttStatement, specTestDecodeHex(t, clientDataJSONHex)
}

func reuseE2EEncode(t *testing.T, rawAuthData []byte, format string, attStmt map[string]any) []byte {
	t.Helper()

	object := map[string]any{stmtAuthData: rawAuthData, stmtFmt: format}

	if attStmt != nil {
		object[stmtAttStmt] = attStmt
	}

	data, err := cbor.Marshal(object)
	require.NoError(t, err)

	return data
}

func compoundE2EEncode(t *testing.T, rawAuthData []byte, statements ...map[string]any) []byte {
	t.Helper()

	subs := make([]any, len(statements))

	for i, statement := range statements {
		subs[i] = map[string]any{
			stmtFmt:     string(AttestationFormatPacked),
			stmtAttStmt: statement,
		}
	}

	data, err := cbor.Marshal(map[string]any{
		stmtAuthData: rawAuthData,
		stmtFmt:      string(AttestationFormatCompound),
		stmtAttStmt:  subs,
	})
	require.NoError(t, err)

	return data
}
