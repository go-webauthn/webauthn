package protocol

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthenticatorData_Unmarshal_CredentialPublicKeyReencodingExpands(t *testing.T) {
	rawPublicKey, err := hex.DecodeString("f9f4cb")
	require.NoError(t, err)

	rawAuthData := buildAuthData(0xC0, nil, rawPublicKey)

	var a AuthenticatorData

	require.NotPanics(t, func() {
		err = a.Unmarshal(rawAuthData)
	})

	assert.Error(t, err)
}

func TestAuthenticatorData_Unmarshal_CredentialPublicKeyReencodingShrinks(t *testing.T) {
	rawPublicKey, err := hex.DecodeString("a119000102")
	require.NoError(t, err)

	rawAuthData := buildAuthData(0xC0, nil, rawPublicKey)

	var a AuthenticatorData

	require.NotPanics(t, func() {
		err = a.Unmarshal(rawAuthData)
	})

	assert.Error(t, err)
	assert.Empty(t, a.ExtData)
}

func TestAuthenticatorData_Unmarshal_TrailingBytesRejected(t *testing.T) {
	rawPublicKey, err := hex.DecodeString("a10102ff")
	require.NoError(t, err)

	rawAuthData := buildAuthData(0x40, nil, rawPublicKey)

	var a AuthenticatorData

	require.NotPanics(t, func() {
		err = a.Unmarshal(rawAuthData)
	})

	assert.EqualError(t, err, "Leftover bytes decoding AuthenticatorData")
}

func buildAuthData(flags byte, credentialID, rawPublicKey []byte) []byte {
	data := make([]byte, 0, 55+len(credentialID)+len(rawPublicKey))

	data = append(data, make([]byte, 32)...)    // RPIDHash.
	data = append(data, flags)                  // Flags.
	data = append(data, 0x00, 0x00, 0x00, 0x01) // Counter.
	data = append(data, make([]byte, 16)...)    // AAGUID.
	data = append(data, byte(len(credentialID)>>8), byte(len(credentialID))) //nolint:gosec // Test data is bounded.
	data = append(data, credentialID...)
	data = append(data, rawPublicKey...)

	return data
}