package protocol

import (
	"math"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol/webauthncbor"
)

func TestParseAuthenticatorExtensionOutputs(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{
		"credProtect":  uint64(3),
		"minPinLength": uint64(6),
		"credBlob":     true,
		"hmac-secret":  true,
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)
	require.NotNil(t, have)

	require.NotNil(t, have.CredProtect)
	assert.Equal(t, CredentialProtectionPolicyUserVerificationRequired, *have.CredProtect)

	require.NotNil(t, have.MinPinLength)
	assert.Equal(t, uint(6), *have.MinPinLength)

	require.NotNil(t, have.CredBlobSet)
	assert.True(t, *have.CredBlobSet)
	assert.Nil(t, have.CredBlob)

	require.NotNil(t, have.HMACSecret)
	assert.True(t, *have.HMACSecret)

	assert.Empty(t, have.Extra)
}

func TestParseAuthenticatorExtensionOutputsAssertionForms(t *testing.T) {
	// credBlob and hmac-secret are polymorphic by ceremony: boolean at registration, byte string at assertion.
	data, err := webauthncbor.Marshal(map[string]any{
		"credBlob":    []byte{0x01, 0x02},
		"hmac-secret": []byte{0x03, 0x04},
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, []byte{0x01, 0x02}, have.CredBlob)
	assert.Nil(t, have.CredBlobSet)
	assert.Equal(t, []byte{0x03, 0x04}, have.HMACSecretV)
	assert.Nil(t, have.HMACSecret)
}

func TestParseAuthenticatorExtensionOutputsUVM(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{
		"uvm": []any{
			[]any{uint64(2), uint64(4), uint64(2)},
			[]any{uint64(4), uint64(2), uint64(4)},
		},
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, []UserVerificationMethod{
		{UserVerificationMethod: 2, KeyProtectionType: 4, MatcherProtectionType: 2},
		{UserVerificationMethod: 4, KeyProtectionType: 2, MatcherProtectionType: 4},
	}, have.UVM)
}

func TestParseAuthenticatorExtensionOutputsUVMFieldOutOfRange(t *testing.T) {
	// A uvm field value that cannot fit in a uint32 is preserved in Extra rather than silently truncated.
	data, err := webauthncbor.Marshal(map[string]any{
		"uvm": []any{
			[]any{uint64(math.MaxUint32) + 1, uint64(4), uint64(2)},
		},
	})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Nil(t, have.UVM)
	require.Contains(t, have.Extra, "uvm")
}

func TestParseAuthenticatorExtensionOutputsUnknownKey(t *testing.T) {
	data, err := webauthncbor.Marshal(map[string]any{"vendorThing": "x"})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Equal(t, map[string]any{"vendorThing": "x"}, have.Extra)
}

func TestParseAuthenticatorExtensionOutputsWrongTypeIsPreserved(t *testing.T) {
	// A known key carrying an unexpected type is preserved rather than failing the ceremony, so one vendor's odd
	// encoding cannot break registration for that authenticator.
	data, err := webauthncbor.Marshal(map[string]any{"minPinLength": "six"})
	require.NoError(t, err)

	have, err := ParseAuthenticatorExtensionOutputs(data)
	require.NoError(t, err)

	assert.Nil(t, have.MinPinLength)
	assert.Equal(t, map[string]any{"minPinLength": "six"}, have.Extra)
}

func TestParseAuthenticatorExtensionOutputsMalformed(t *testing.T) {
	// Structurally invalid CBOR is signed data that failed to parse; that is a hard error.
	_, err := ParseAuthenticatorExtensionOutputs([]byte{0xff, 0xff, 0xff})

	assert.Error(t, err)
}
