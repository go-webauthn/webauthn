package protocol

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"math"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func FuzzParseCredentialCreationResponseBytes(f *testing.F) {
	for _, vector := range fuzzSpecVectorsRegistration {
		f.Add(fuzzBuildRegistrationJSON(f, vector.credentialID, vector.attestationObject, vector.clientDataJSON))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		pcc, err := ParseCredentialCreationResponseBytes(data)
		if err != nil {
			require.Nil(t, pcc, "a failed parse must not return a partially populated result")

			return
		}

		require.NotNil(t, pcc)

		raw, err := base64.RawURLEncoding.DecodeString(pcc.ID)

		require.NoError(t, err)
		require.Equal(t, pcc.RawID, raw)

		require.Len(t, pcc.Response.AttestationObject.AuthData.RPIDHash, 32)
		require.True(t, pcc.Response.AttestationObject.AuthData.Flags.HasAttestedCredentialData())
	})
}

func FuzzParseCredentialRequestResponseBytes(f *testing.F) {
	for _, vector := range fuzzSpecVectorsAssertion {
		f.Add(fuzzBuildAssertionJSON(f, vector.credentialID, vector.authenticatorData, vector.clientDataJSON, vector.signature))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		par, err := ParseCredentialRequestResponseBytes(data)
		if err != nil {
			require.Nil(t, par, "a failed parse must not return a partially populated result")

			return
		}

		require.NotNil(t, par)

		raw, err := base64.RawURLEncoding.DecodeString(par.ID)

		require.NoError(t, err)
		require.Equal(t, par.RawID, raw)
		require.Len(t, par.Response.AuthenticatorData.RPIDHash, 32)
	})
}

func FuzzAuthenticatorDataUnmarshal(f *testing.F) {
	for _, seed := range fuzzSeedsAuthenticatorData(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		a := AuthenticatorData{}

		if err := a.Unmarshal(data); err != nil {
			return
		}

		require.Equal(t, data[:32], a.RPIDHash)
		require.Equal(t, AuthenticatorFlags(data[32]), a.Flags)
		require.Equal(t, binary.BigEndian.Uint32(data[33:37]), a.Counter)

		require.Equal(t, a.Flags.HasExtensions(), len(a.ExtData) > 0)

		if len(a.ExtData) > 0 {
			require.Equal(t, data[len(data)-len(a.ExtData):], a.ExtData)
		}

		if !a.Flags.HasAttestedCredentialData() {
			require.Equal(t, minAuthDataLength+len(a.ExtData), len(data))

			return
		}

		require.Equal(t, data[37:53], a.AttData.AAGUID)
		require.LessOrEqual(t, len(a.AttData.CredentialID), maxCredentialIDLength)
		require.Equal(t, int(binary.BigEndian.Uint16(data[53:55])), len(a.AttData.CredentialID))
		require.Equal(t, data[55:55+len(a.AttData.CredentialID)], a.AttData.CredentialID)

		start, end := minAttestedAuthLength+len(a.AttData.CredentialID), len(data)-len(a.ExtData)

		require.Greater(t, end, start)

		var m any

		n, err := webauthncbor.UnmarshalFirst(data[start:end], &m)

		require.NoError(t, err)
		require.Equal(t, end-start, n)

		n, err = webauthncbor.UnmarshalFirst(a.AttData.CredentialPublicKey, &m)

		require.NoError(t, err)
		require.Len(t, a.AttData.CredentialPublicKey, n)
	})
}

func FuzzAttestationObjectUnmarshalCBOR(f *testing.F) {
	for _, vector := range fuzzSpecVectorsRegistration {
		f.Add(fuzzDecodeHex(f, vector.attestationObject))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		fresh := AttestationObject{}
		errFresh := fresh.UnmarshalCBOR(data)

		reused := AttestationObject{
			Format:        "packed",
			RawAuthData:   []byte{0x00},
			AttStatement:  map[string]any{"alg": int64(-7), "sig": []byte{0x00}},
			SubStatements: []NonCompoundAttestationObject{{Format: "none"}},
		}
		errReused := reused.UnmarshalCBOR(data)

		require.Equal(t, errFresh == nil, errReused == nil)

		if errFresh != nil {
			return
		}

		require.Equal(t, fresh, reused, "decoding into a reused receiver must replace it rather than merge into it")
		require.True(t, fresh.AttStatement == nil || fresh.SubStatements == nil)
	})
}

func FuzzParseAuthenticatorExtensionOutputs(f *testing.F) {
	for _, seed := range fuzzSeedsExtensionOutputs(f) {
		f.Add(seed)
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		first, err := ParseAuthenticatorExtensionOutputs(data)
		if err != nil {
			require.Nil(t, first)

			return
		}

		require.NotNil(t, first)

		if fuzzContainsNaN(first.Extra) {
			return
		}

		for range 3 {
			again, err := ParseAuthenticatorExtensionOutputs(data)

			require.NoError(t, err)
			require.Equal(t, first, again, "the parse must not depend on map iteration order")
		}
	})
}

// Supporting constants, variables, and functions.

// The seed vectors are the WebAuthn Level 3 §16 end-to-end test vectors, which
// specification_vectors_e2e_test.go verifies in full. They are repeated here rather than shared with those tests so
// that the corpus a target starts from is visible at the target, and so that narrowing a test case does not silently
// narrow the corpus.
//
// See: https://www.w3.org/TR/webauthn-3/#sctn-test-vectors
var (
	//nolint:gosec
	fuzzSpecVectorsRegistration = []struct {
		name              string
		credentialID      string
		attestationObject string
		clientDataJSON    string
	}{
		{
			// §16.2 None Attestation - ES256.
			name:              "NoneES256",
			credentialID:      "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4",
			attestationObject: "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b559000000008446ccb9ab1db374750b2367ff6f3a1f0020f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4a5010203262001215820afefa16f97ca9b2d23eb86ccb64098d20db90856062eb249c33a9b672f26df61225820930a56b87a2fca66334b03458abf879717c12cc68ed73290af2e2664796b9220",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a22414d4d507434557878475453746e63647134313759447742466938767049612d7077386f4f755657345441222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a20426b5165446a646354427258426941774a544c453551227d",
		},
		{
			// §16.3 Self Attestation (Packed) - ES256. The only seed carrying an attestation statement, so the only
			// one which reaches the second decoding pass in AttestationObject.UnmarshalCBOR.
			name:              "PackedSelfES256",
			credentialID:      "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c",
			attestationObject: "a363666d74667061636b65646761747453746d74a263616c672663736967584630440220067a20754ab925005dbf378097c92120031581c73228d1fb4f5b881bcd7da98302207fc7b147558c7c0eba3af18bd9d121fa3d3a26d17fe3f220272178f473b6006d68617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b55d00000000df850e09db6afbdfab51697791506cfc0020455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58ca5010203262001215820eb151c8176b225cc651559fecf07af450fd85802046656b34c18f6cf193843c5225820927b8aa427a2be1b8834d233a2d34f61f13bfd44119c325d5896e183fee484f2",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a2265476e4374334c55745936366b336a506a796e6962506b31716e666644616966715a774c33417032392d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a205539685458764b453255526b4d6e625f307859485667227d",
		},
		{
			// §16.5 None Attestation - ES256 - Top Origin.
			name:              "NoneES256TopOrigin",
			credentialID:      "b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1",
			attestationObject: "a363666d74646e6f6e656761747453746d74a068617574684461746158a4bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b5410000000097586fd09799a76401c200455099ef2a0020b8ad59b996047ab18e2ceb57206c362da57458793481f4a8ebf101c7ca7cc0f1a5010203262001215820a1c47c1d82da4ebe82cd72207102b380670701993bc35398ae2e5726427fe01d22582086c1080d82987028c7f54ecb1b01185de243b359294a0ed210cd47480f0adc88",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e637265617465222c226368616c6c656e6765223a225468394d595a68706e6a504254786b68555f53646667364f4e58665672454673587a72636b7151664a2d55222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a747275652c22746f704f726967696e223a2268747470733a2f2f6578616d706c652e636f6d227d",
		},
	}

	//nolint:gosec
	fuzzSpecVectorsAssertion = []struct {
		name              string
		credentialID      string
		authenticatorData string
		clientDataJSON    string
		signature         string
	}{
		{
			// §16.2 None Attestation - ES256 (Authentication).
			name:              "NoneES256",
			credentialID:      "f91f391db4c9b2fde0ea70189cba3fb63f579ba6122b33ad94ff3ec330084be4",
			authenticatorData: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b51900000000",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a224f63446e55685158756c5455506f334a5558543049393770767a7a59425039745a63685879617630314167222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73657d",
			signature:         "3046022100f50a4e2e4409249c4a853ba361282f09841df4dd4547a13a87780218deffcd380221008480ac0f0b93538174f575bf11a1dd5d78c6e486013f937295ea13653e331e87",
		},
		{
			// §16.3 Self Attestation (Packed) - ES256 (Authentication).
			name:              "PackedSelfES256",
			credentialID:      "455ef34e2043a87db3d4afeb39bbcb6cc32df9347c789a865ecdca129cbef58c",
			authenticatorData: "bfabc37432958b063360d3ad6461c9c4735ae7f8edd46592a5e0f01452b2e4b50900000000",
			clientDataJSON:    "7b2274797065223a22776562617574686e2e676574222c226368616c6c656e6765223a225248696843784e534e493352594d45314f7731476d3132786e726b634a5f6666707637546e2d4a71386773222c226f726967696e223a2268747470733a2f2f6578616d706c652e6f7267222c2263726f73734f726967696e223a66616c73652c22657874726144617461223a22636c69656e74446174614a534f4e206d617920626520657874656e6465642077697468206164646974696f6e616c206669656c647320696e20746865206675747572652c207375636820617320746869733a206754623533727a36456853576f6d58477a696d433151227d",
			signature:         "304402203310b9431903c401f1be2bdc8d23a4007682dbbddcf846994947b7f465daf84002204e94dd00047b316061b3b99772b7efd95994a83ef584b3b6b825ea3550251b66",
		},
	}
)

// fuzzContainsNaN reports whether a value decoded from CBOR carries a floating point NaN anywhere within it. A NaN is
// not equal to itself under the reflective equality require.Equal uses, so a result which retains one cannot be
// compared to another result by that means, and an equality assertion over it reports a difference which is not there.
func fuzzContainsNaN(v any) bool {
	switch value := v.(type) {
	case float64:
		return math.IsNaN(value)
	case float32:
		return math.IsNaN(float64(value))
	case []any:
		for _, element := range value {
			if fuzzContainsNaN(element) {
				return true
			}
		}
	case map[string]any:
		for _, element := range value {
			if fuzzContainsNaN(element) {
				return true
			}
		}
	case map[any]any:
		for key, element := range value {
			if fuzzContainsNaN(key) || fuzzContainsNaN(element) {
				return true
			}
		}
	}

	return false
}

func fuzzDecodeHex(tb testing.TB, s string) []byte {
	tb.Helper()

	data, err := hex.DecodeString(s)
	require.NoError(tb, err)

	return data
}

func fuzzHexToBase64URL(tb testing.TB, s string) string {
	tb.Helper()

	return base64.RawURLEncoding.EncodeToString(fuzzDecodeHex(tb, s))
}

func fuzzBuildRegistrationJSON(tb testing.TB, credentialIDHex, attestationObjectHex, clientDataJSONHex string) []byte {
	tb.Helper()

	id := fuzzHexToBase64URL(tb, credentialIDHex)

	data, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"attestationObject": fuzzHexToBase64URL(tb, attestationObjectHex),
			"clientDataJSON":    fuzzHexToBase64URL(tb, clientDataJSONHex),
		},
	})
	require.NoError(tb, err)

	return data
}

func fuzzBuildAssertionJSON(tb testing.TB, credentialIDHex, authenticatorDataHex, clientDataJSONHex, signatureHex string) []byte {
	tb.Helper()

	id := fuzzHexToBase64URL(tb, credentialIDHex)

	data, err := json.Marshal(map[string]any{
		"id":    id,
		"rawId": id,
		"type":  "public-key",
		"response": map[string]any{
			"authenticatorData": fuzzHexToBase64URL(tb, authenticatorDataHex),
			"clientDataJSON":    fuzzHexToBase64URL(tb, clientDataJSONHex),
			"signature":         fuzzHexToBase64URL(tb, signatureHex),
		},
	})
	require.NoError(tb, err)

	return data
}

// fuzzSeedsAuthenticatorData collects authenticator data in both of the shapes the parser accepts: the assertion form,
// which is the fixed header alone, and the registration form, which carries attested credential data. The latter is
// taken from the attestation objects rather than repeated as its own constant so that the two cannot drift apart.
func fuzzSeedsAuthenticatorData(tb testing.TB) (seeds [][]byte) {
	tb.Helper()

	for _, vector := range fuzzSpecVectorsAssertion {
		seeds = append(seeds, fuzzDecodeHex(tb, vector.authenticatorData))
	}

	for _, vector := range fuzzSpecVectorsRegistration {
		attestation := AttestationObject{}

		require.NoError(tb, webauthncbor.Unmarshal(fuzzDecodeHex(tb, vector.attestationObject), &attestation))
		require.NotEmpty(tb, attestation.RawAuthData)

		seeds = append(seeds, attestation.RawAuthData)
	}

	// The extension data flag is not set by any of the spec vectors, so a seed carrying extension outputs is appended
	// to one of them. Without this the fuzzer has to discover both the flag and a well formed CBOR map at the tail
	// before it reaches the branch which places the extension data.
	base := seeds[0]

	extended := bytes.Clone(base)
	extended[32] |= 0x80

	seeds = append(seeds, append(extended, fuzzSeedsExtensionOutputs(tb)[0]...))

	return seeds
}

// fuzzSeedsExtensionOutputs builds the extension output maps rather than repeating them as encoded constants, so that
// a seed remains a valid encoding of what it claims to be if the encoder's canonical form changes.
func fuzzSeedsExtensionOutputs(tb testing.TB) (seeds [][]byte) {
	tb.Helper()

	for _, members := range []map[string]any{
		{},
		{ExtensionCredProtect: uint64(2)},
		{ExtensionHMACSecret: true},
		// Both credential protection identifiers at once, which is the case the parser resolves deliberately rather
		// than by map iteration order.
		{ExtensionCredProtect: uint64(3), ExtensionCredentialProtectionPolicy: uint64(1)},
		{ExtensionCredProtect: uint64(1), ExtensionHMACSecret: false, "unmodelled": []byte{0x01, 0x02}},
	} {
		data, err := webauthncbor.Marshal(members)
		require.NoError(tb, err)

		seeds = append(seeds, data)
	}

	return seeds
}
