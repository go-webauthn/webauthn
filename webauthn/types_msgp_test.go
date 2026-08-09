package webauthn

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/tinylib/msgp/msgp"

	"github.com/go-webauthn/webauthn/protocol"
)

// msgpCodec is the full set of methods msgp generates for a type. The generated code implements each of the four
// entry points separately, so exercising only the buffer pair leaves the streaming pair untested even though both
// are part of the persistence contract a Relying Party depends on.
type msgpCodec interface {
	msgp.Encodable
	msgp.Decodable
	msgp.Marshaler
	msgp.Unmarshaler
	msgp.Sizer
}

// exerciseMsgpCodec round trips a value through both the buffer pair (MarshalMsg/UnmarshalMsg) and the streaming
// pair (EncodeMsg/DecodeMsg), asserting the two encoders agree and that each decoder reconstructs the original.
//
// fresh must return a zero value of the same concrete type, so the comparison is against a destination which
// carried nothing over from the source.
func exerciseMsgpCodec(t *testing.T, populated msgpCodec, fresh func() msgpCodec) []byte {
	t.Helper()

	marshalled, err := populated.MarshalMsg(nil)
	require.NoError(t, err)

	assert.LessOrEqual(t, len(marshalled), populated.Msgsize(),
		"Msgsize must be an upper bound on the encoded size, otherwise callers sizing buffers from it under-allocate")

	// Comparing the re-encoded form rather than the structs keeps the assertion on what the codec is responsible
	// for. A time.Time round trips to an equal instant but not to a deeply equal value, because it carries an
	// unexported location pointer and monotonic reading which the wire format neither holds nor should hold.
	requireReEncodes := func(t *testing.T, decoded msgpCodec) {
		t.Helper()

		again, err := decoded.MarshalMsg(nil)
		require.NoError(t, err)
		assert.Equal(t, marshalled, again, "the decoded value must re-encode to the bytes it came from")
	}

	t.Run("BufferRoundTrip", func(t *testing.T) {
		decoded := fresh()

		left, err := decoded.UnmarshalMsg(marshalled)
		require.NoError(t, err)
		assert.Empty(t, left)
		requireReEncodes(t, decoded)
	})

	t.Run("StreamRoundTrip", func(t *testing.T) {
		var buf bytes.Buffer

		require.NoError(t, msgp.Encode(&buf, populated))

		// The two encoders are generated separately from the same field list, so they are only known to agree if
		// their output is compared; a field written by one and not the other would otherwise go unnoticed.
		assert.Equal(t, marshalled, buf.Bytes(), "EncodeMsg and MarshalMsg must produce identical bytes")

		decoded := fresh()

		require.NoError(t, msgp.Decode(&buf, decoded))
		requireReEncodes(t, decoded)
	})

	t.Run("DecodeTruncated", func(t *testing.T) {
		// Every field read in the generated decoders is followed by an error branch that only a short buffer
		// reaches. Sweeping the prefixes walks all of them for both decoders.
		for limit := range len(marshalled) {
			truncated := marshalled[:limit]

			decoded := fresh()

			_, err := decoded.UnmarshalMsg(truncated)
			require.Errorf(t, err, "UnmarshalMsg must fail on a %d of %d byte prefix", limit, len(marshalled))

			streamed := fresh()

			require.Errorf(t, msgp.Decode(bytes.NewReader(truncated), streamed),
				"DecodeMsg must fail on a %d of %d byte prefix", limit, len(marshalled))
		}
	})

	return marshalled
}

func TestMsgpCodecs(t *testing.T) {
	// Each value is fully populated: the generated encoders emit a field only when it is non-zero, so a zero value
	// exercises the omitted branch of every field and nothing else. The generated tests cover that case already.
	testCases := []struct {
		name      string
		populated msgpCodec
		fresh     func() msgpCodec
	}{
		{
			name:      "Credential",
			populated: ptr(newPopulatedCredentialWithEverything()),
			fresh:     func() msgpCodec { return &Credential{} },
		},
		{
			name:      "CredentialZero",
			populated: &Credential{},
			fresh:     func() msgpCodec { return &Credential{} },
		},
		{
			name:      "CredentialExtensions",
			populated: ptr(newPopulatedCredentialExtensions()),
			fresh:     func() msgpCodec { return &CredentialExtensions{} },
		},
		{
			name:      "CredentialExtensionsZero",
			populated: &CredentialExtensions{},
			fresh:     func() msgpCodec { return &CredentialExtensions{} },
		},
		{
			name:      "CredentialAttestation",
			populated: ptr(newPopulatedCredentialWithEverything().Attestation),
			fresh:     func() msgpCodec { return &CredentialAttestation{} },
		},
		{
			name:      "CredentialFlags",
			populated: &CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: true},
			fresh:     func() msgpCodec { return &CredentialFlags{} },
		},
		{
			name:      "Credentials",
			populated: &Credentials{newPopulatedCredentialWithEverything(), newPopulatedCredential()},
			fresh:     func() msgpCodec { return &Credentials{} },
		},
		{
			name:      "Authenticator",
			populated: ptr(newPopulatedCredentialWithEverything().Authenticator),
			fresh:     func() msgpCodec { return &Authenticator{} },
		},
		{
			name:      "SessionData",
			populated: ptr(newPopulatedSessionData()),
			fresh:     func() msgpCodec { return &SessionData{} },
		},
		{
			name:      "SessionDataZero",
			populated: &SessionData{},
			fresh:     func() msgpCodec { return &SessionData{} },
		},
		{
			name:      "SessionExtensions",
			populated: ptr(newPopulatedSessionExtensions()),
			fresh:     func() msgpCodec { return &sessionExtensions{} },
		},
		{
			name:      "SessionExtensionsZero",
			populated: &sessionExtensions{},
			fresh:     func() msgpCodec { return &sessionExtensions{} },
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			exerciseMsgpCodec(t, tc.populated, tc.fresh)
		})
	}
}

func TestMsgpEncodeErrorPaths(t *testing.T) {
	// The encoders write each field through a writer which can fail at any point. Sweeping the failure offset
	// reaches the error branch that follows every individual write.
	testCases := []struct {
		name      string
		populated msgpCodec
	}{
		{"Credential", ptr(newPopulatedCredentialWithEverything())},
		{"CredentialExtensions", ptr(newPopulatedCredentialExtensions())},
		{"CredentialFlags", &CredentialFlags{UserPresent: true, UserVerified: true, BackupEligible: true, BackupState: true}},
		{"Credentials", &Credentials{newPopulatedCredentialWithEverything()}},
		{"Authenticator", ptr(newPopulatedCredentialWithEverything().Authenticator)},
		{"SessionData", ptr(newPopulatedSessionData())},
		{"SessionExtensions", ptr(newPopulatedSessionExtensions())},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			marshalled, err := tc.populated.MarshalMsg(nil)
			require.NoError(t, err)

			exerciseEncodeMsgErrorPaths(t, tc.populated, marshalled)
		})
	}
}

// TestMsgpDecodeWrongFieldTypes covers the per-field type assertions in the decoders. A stored record whose field
// carries the wrong type must be reported against that field rather than decoding to a silently wrong value.
func TestMsgpDecodeWrongFieldTypes(t *testing.T) {
	testCases := []struct {
		name  string
		key   string
		value []byte
		fresh func() msgpCodec
	}{
		{"CredentialID", "id", msgpString("not-bytes"), func() msgpCodec { return &Credential{} }},
		{"CredentialAttestationType", "atttype", msgpInt64(1), func() msgpCodec { return &Credential{} }},
		{"CredentialExtensionsRK", "rk", msgpString("yes"), func() msgpCodec { return &CredentialExtensions{} }},
		{"CredentialExtensionsCredProtect", "cp", msgpInt64(3), func() msgpCodec { return &CredentialExtensions{} }},
		{"CredentialExtensionsMinPinLength", "mpl", msgpString("six"), func() msgpCodec { return &CredentialExtensions{} }},
		{"CredentialExtensionsPRF", "prf", msgpString("yes"), func() msgpCodec { return &CredentialExtensions{} }},
		{"CredentialExtensionsLargeBlob", "lbs", msgpString("yes"), func() msgpCodec { return &CredentialExtensions{} }},
		{"CredentialExtensionsHMACSecret", "hs", msgpString("yes"), func() msgpCodec { return &CredentialExtensions{} }},
		{"CredentialExtensionsCredBlobSet", "cbs", msgpString("yes"), func() msgpCodec { return &CredentialExtensions{} }},
		{"SessionDataChallenge", "c", msgpInt64(1), func() msgpCodec { return &SessionData{} }},
		{"SessionExtensionsAppID", "appid", msgpInt64(1), func() msgpCodec { return &sessionExtensions{} }},
		{"SessionExtensionsLargeBlobRead", "lbRead", msgpString("yes"), func() msgpCodec { return &sessionExtensions{} }},
		{"SessionExtensionsCredProtect", "credProtect", msgpInt64(1), func() msgpCodec { return &sessionExtensions{} }},
		{"SessionExtensionsCPEnforce", "cpEnforce", msgpString("yes"), func() msgpCodec { return &sessionExtensions{} }},
		{"SessionExtensionsCredBlob", "credBlob", msgpString("yes"), func() msgpCodec { return &sessionExtensions{} }},
		{"SessionExtensionsRequested", "req", msgpString("appid"), func() msgpCodec { return &sessionExtensions{} }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := msgpOneFieldMap(tc.key, tc.value)

			decoded := tc.fresh()
			_, err := decoded.UnmarshalMsg(payload)
			require.Error(t, err, "UnmarshalMsg must reject the wrong type")

			streamed := tc.fresh()
			require.Error(t, msgp.Decode(bytes.NewReader(payload), streamed), "DecodeMsg must reject the wrong type")
		})
	}
}

// TestMsgpDecodeUnknownField covers the skip path both decoders take for a member they do not model, which is what
// lets a record written by a newer release be read by an older one.
func TestMsgpDecodeUnknownField(t *testing.T) {
	testCases := []struct {
		name  string
		fresh func() msgpCodec
	}{
		{"Credential", func() msgpCodec { return &Credential{} }},
		{"CredentialExtensions", func() msgpCodec { return &CredentialExtensions{} }},
		{"Authenticator", func() msgpCodec { return &Authenticator{} }},
		{"SessionData", func() msgpCodec { return &SessionData{} }},
		{"SessionExtensions", func() msgpCodec { return &sessionExtensions{} }},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			payload := msgpOneFieldMap("fieldFromANewerRelease", msgpString("x"))

			decoded := tc.fresh()

			left, err := decoded.UnmarshalMsg(payload)
			require.NoError(t, err)
			assert.Empty(t, left)

			streamed := tc.fresh()
			require.NoError(t, msgp.Decode(bytes.NewReader(payload), streamed))
		})
	}
}

func newPopulatedCredentialExtensions() CredentialExtensions {
	return CredentialExtensions{
		RK:                 ptr(true),
		CredProtect:        protocol.CredentialProtectionPolicyUserVerificationRequired,
		MinPinLength:       ptr(uint(6)),
		PRFEnabled:         ptr(true),
		LargeBlobSupported: ptr(true),
		HMACSecret:         ptr(true),
		CredBlobSet:        ptr(true),
	}
}

func newPopulatedSessionExtensions() sessionExtensions {
	return sessionExtensions{
		Requested:                         []string{protocol.ExtensionAppID, protocol.ExtensionCredProps},
		AppID:                             "https://example.com",
		AppIDExclude:                      "https://exclude.example.com",
		LargeBlob:                         protocol.LargeBlobSupportRequired,
		LargeBlobRead:                     true,
		LargeBlobWrite:                    true,
		CredentialProtectionPolicy:        protocol.CredentialProtectionPolicyUserVerificationRequired,
		EnforceCredentialProtectionPolicy: true,
		CredBlob:                          true,
		Extra:                             map[string]any{"vendorThing": "x"},
	}
}

// newPopulatedCredentialWithEverything is newPopulatedCredential with every optional member set, so the encoders
// emit each field rather than skipping it.
func newPopulatedCredentialWithEverything() Credential {
	credential := newPopulatedCredential()

	credential.Extensions = newPopulatedCredentialExtensions()
	credential.Authenticator.Attachment = protocol.CrossPlatform

	return credential
}

// TestMsgpDecodeExplicitNil covers the nil arm of every pointer field in the decoders. The encoders omit a nil
// pointer rather than writing one, so this shape is only produced by another writer, but both decoders accept it
// and a record carrying explicit nils has to decode to the same value as one that omits the members.
func TestMsgpDecodeExplicitNil(t *testing.T) {
	payload := msgp.AppendMapHeader(nil, 7)

	for _, key := range []string{"rk", "mpl", "prf", "lbs", "hs", "cbs"} {
		payload = msgp.AppendString(payload, key)
		payload = msgp.AppendNil(payload)
	}

	// CredProtect is a string rather than a pointer, so it carries an empty value rather than a nil.
	payload = msgp.AppendString(payload, "cp")
	payload = msgp.AppendString(payload, "")

	t.Run("Buffer", func(t *testing.T) {
		var decoded CredentialExtensions

		left, err := decoded.UnmarshalMsg(payload)
		require.NoError(t, err)
		assert.Empty(t, left)
		assert.Equal(t, CredentialExtensions{}, decoded)
	})

	t.Run("Stream", func(t *testing.T) {
		var decoded CredentialExtensions

		require.NoError(t, msgp.Decode(bytes.NewReader(payload), &decoded))
		assert.Equal(t, CredentialExtensions{}, decoded)
	})

	t.Run("OverwritesAPopulatedDestination", func(t *testing.T) {
		// The decoders assign through the existing pointer when one is already set, so a reused destination must
		// still end up nil rather than retaining the previous record's value.
		decoded := newPopulatedCredentialExtensions()

		_, err := decoded.UnmarshalMsg(payload)
		require.NoError(t, err)
		assert.Equal(t, CredentialExtensions{}, decoded)
	})

	t.Run("Truncated", func(t *testing.T) {
		for limit := range len(payload) {
			var decoded CredentialExtensions

			_, err := decoded.UnmarshalMsg(payload[:limit])
			require.Errorf(t, err, "UnmarshalMsg must fail on a %d of %d byte prefix", limit, len(payload))

			var streamed CredentialExtensions

			require.Errorf(t, msgp.Decode(bytes.NewReader(payload[:limit]), &streamed),
				"DecodeMsg must fail on a %d of %d byte prefix", limit, len(payload))
		}
	})
}
