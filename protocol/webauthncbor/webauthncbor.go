package webauthncbor

import cbor "github.com/fxamacker/cbor/v2"

// nestedLevelsAllowed bounds the depth of the CBOR structures this package will decode.
//
// CTAP2 limits its own message encodings to 4 levels of any combination of maps and arrays. The attestation object is a
// WebAuthn structure rather than a CTAP message though, and the compound attestation statement format introduced by
// WebAuthn Level 3 needs 5.
//
// Specification: §8.9. Compound Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation)
const nestedLevelsAllowed = 5

// RawMessage is a raw encoded CBOR value, which callers can use to defer the decoding of a member whose shape
// depends on another member of the same structure. It is an alias so that a value of this type satisfies the
// underlying library's own marshalling interfaces, and exists so that consumers of this package do not have to
// import that library directly.
type RawMessage = cbor.RawMessage

// ctap2CBORDecMode is the cbor.DecMode following the CTAP2 canonical CBOR encoding form
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
var ctap2CBORDecMode, _ = cbor.DecOptions{
	DupMapKey:       cbor.DupMapKeyEnforcedAPF,
	MaxNestedLevels: nestedLevelsAllowed,
	IndefLength:     cbor.IndefLengthForbidden,
	TagsMd:          cbor.TagsForbidden,
}.DecMode()

var ctap2CBOREncMode, _ = cbor.CTAP2EncOptions().EncMode()

// Unmarshal parses the CBOR-encoded data into the value pointed to by v
// following the CTAP2 canonical CBOR encoding form.
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
//
// The data must hold exactly one CBOR item. Bytes which follow that item are malformed input rather than something to
// discard, so they are reported. Callers decoding an item embedded in a larger byte sequence want [UnmarshalFirst].
func Unmarshal(data []byte, v any) error {
	return ctap2CBORDecMode.Unmarshal(data, v)
}

// UnmarshalFirst parses the first CBOR-encoded item in data into the value pointed to by v following the CTAP2
// canonical CBOR encoding form, and returns the number of bytes of data which that item consumed. Callers which decode
// an item embedded in a larger byte sequence must use this rather than deriving a length from the re-encoded output of
// Marshal, as the encoded form is not guaranteed to be the same size as the form which was decoded.
func UnmarshalFirst(data []byte, v any) (n int, err error) {
	var rest []byte

	if rest, err = ctap2CBORDecMode.UnmarshalFirst(data, v); err != nil {
		return 0, err
	}

	return len(data) - len(rest), nil
}

// Marshal encodes the value pointed to by v
// following the CTAP2 canonical CBOR encoding form.
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
func Marshal(v any) ([]byte, error) {
	return ctap2CBOREncMode.Marshal(v)
}
