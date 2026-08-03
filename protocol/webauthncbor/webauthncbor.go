package webauthncbor

import "github.com/fxamacker/cbor/v2"

const nestedLevelsAllowed = 4

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
func Unmarshal(data []byte, v any) error {
	_, err := ctap2CBORDecMode.UnmarshalFirst(data, v)

	return err
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
