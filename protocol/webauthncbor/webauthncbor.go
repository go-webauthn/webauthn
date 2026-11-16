package webauthncbor

import (
	"fmt"
	"io"

	cbor "github.com/fxamacker/cbor/v2"
)

// nestedLevelsAllowed bounds the depth of the CBOR structures this package will decode.
//
// CTAP2 limits its own message encodings to 4 levels of any combination of maps and arrays. The attestation object is a
// WebAuthn structure rather than a CTAP message though, and the compound attestation statement format introduced by
// WebAuthn Level 3 needs 5.
//
// Specification: §8.9. Compound Attestation Statement Format (https://www.w3.org/TR/webauthn-3/#sctn-compound-attestation)
const nestedLevelsAllowed = 5

const (
	majorTypeByteString = 2
	majorTypeTextString = 3
	majorTypeArray      = 4
	majorTypeMap        = 5
	majorTypeTag        = 6
	majorTypeOther      = 7
)

// RawMessage is a raw encoded CBOR value, which callers can use to defer the decoding of a member whose shape
// depends on another member of the same structure. It is an alias so that a value of this type satisfies the
// underlying library's own marshalling interfaces, and exists so that consumers of this package do not have to
// import that library directly.
type RawMessage = cbor.RawMessage

// ctap2CBORDecMode is the cbor.DecMode which enforces the requirements of the CTAP2 canonical CBOR encoding form the
// underlying library is able to: a map may not repeat a key, an item may not be of an indefinite length, and a tag may
// not be used. See [Unmarshal] for what is and is not enforced on top of it.
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
var ctap2CBORDecMode, _ = cbor.DecOptions{
	DupMapKey:       cbor.DupMapKeyEnforcedAPF,
	MaxNestedLevels: nestedLevelsAllowed,
	IndefLength:     cbor.IndefLengthForbidden,
	TagsMd:          cbor.TagsForbidden,
}.DecMode()

var ctap2CBOREncMode, _ = cbor.CTAP2EncOptions().EncMode()

// Unmarshal parses the CBOR-encoded data into the value pointed to by v, enforcing part of the CTAP2 canonical CBOR
// encoding form.
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
//
// The requirements of that form which are enforced are that every integer and every length is encoded in the fewest
// bytes possible, that no item is of an indefinite length, that no map repeats a key, and that no tag is present.
// Nesting is limited to 5 levels rather than the 4 of that form, which the compound attestation statement format
// exceeds.
//
// The requirement that the keys of a map are sorted is not enforced, as attestation objects produced by clients and
// authenticators in use do not all satisfy it. The representation of a floating point value is not examined either.
// The type of an item is decided by the value it is decoded into rather than by this package, and the underlying
// library decodes an array of integers into a byte slice, so a caller which requires a byte string must check for
// one itself with [IsByteString].
//
// The data must hold exactly one CBOR item. Bytes which follow that item are malformed input rather than something to
// discard, so they are reported. Callers decoding an item embedded in a larger byte sequence want [UnmarshalFirst].
func Unmarshal(data []byte, v any) (err error) {
	if err = ctap2CBORDecMode.Unmarshal(data, v); err != nil {
		return err
	}

	_, err = validateShortestForm(data, 0)

	return err
}

// UnmarshalFirst parses the first CBOR-encoded item in data into the value pointed to by v, enforcing the same
// requirements as [Unmarshal], and returns the number of bytes of data which that item consumed. Callers which decode
// an item embedded in a larger byte sequence must use this rather than deriving a length from the re-encoded output of
// Marshal, as the encoded form is not guaranteed to be the same size as the form which was decoded.
func UnmarshalFirst(data []byte, v any) (n int, err error) {
	var rest []byte

	if rest, err = ctap2CBORDecMode.UnmarshalFirst(data, v); err != nil {
		return 0, err
	}

	n = len(data) - len(rest)

	if _, err = validateShortestForm(data[:n], 0); err != nil {
		return 0, err
	}

	return n, nil
}

// IsByteString reports whether the encoded CBOR item is a byte string. A caller which decodes into a byte slice uses
// it with a [RawMessage] to require one, as the underlying library also decodes an array of integers into a byte
// slice.
func IsByteString(item RawMessage) bool {
	return len(item) != 0 && item[0]>>5 == majorTypeByteString
}

// Marshal encodes the value pointed to by v
// following the CTAP2 canonical CBOR encoding form.
// (https://fidoalliance.org/specs/fido-v2.0-ps-20190130/fido-client-to-authenticator-protocol-v2.0-ps-20190130.html#message-encoding)
func Marshal(v any) ([]byte, error) {
	return ctap2CBOREncMode.Marshal(v)
}

func validateShortestForm(data []byte, offset int) (n int, err error) {
	var (
		major byte
		arg   uint64
	)

	if major, arg, n, err = validateShortestFormHead(data, offset); err != nil {
		return 0, err
	}

	var items uint64

	switch major {
	case majorTypeByteString, majorTypeTextString:
		if arg > uint64(len(data)-offset-n) { //nolint:gosec // The head is within the data, so this is not negative.
			return 0, io.ErrUnexpectedEOF
		}

		return n + int(arg), nil //nolint:gosec // The length is bounded by the length of the data above.
	case majorTypeArray:
		items = arg
	case majorTypeMap:
		if arg > uint64(len(data)) {
			return 0, io.ErrUnexpectedEOF
		}

		items = arg * 2
	case majorTypeTag:
		items = 1
	}

	for range items {
		var m int

		if m, err = validateShortestForm(data, offset+n); err != nil {
			return 0, err
		}

		n += m
	}

	return n, nil
}

func validateShortestFormHead(data []byte, offset int) (major byte, arg uint64, n int, err error) {
	if offset >= len(data) {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}

	major, info := data[offset]>>5, data[offset]&0x1f

	// The additional information values 24 to 27 state that the argument follows in 1, 2, 4, or 8 bytes. The values
	// above them are reserved or mark an indefinite length, and the decoder has rejected both by this point.
	if info < 24 || info > 27 {
		return major, uint64(info), 1, nil
	}

	size := 1 << (info - 24)

	if len(data)-offset-1 < size {
		return 0, 0, 0, io.ErrUnexpectedEOF
	}

	for _, b := range data[offset+1 : offset+1+size] {
		arg = arg<<8 | uint64(b)
	}

	// The argument of major type 7 is a simple value or a floating point value rather than an integer or a length,
	// and the canonical form leaves the representation of a floating point value alone.
	if major != majorTypeOther && (size == 1 && arg < 24 || size > 1 && arg>>(size*4) == 0) {
		return 0, 0, 0, fmt.Errorf("cbor: integer or length at index %d is not encoded in the fewest bytes possible", offset)
	}

	return major, arg, 1 + size, nil
}
