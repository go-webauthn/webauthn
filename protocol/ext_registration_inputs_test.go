package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRegistrationExtensionsClientInputs_JSON(t *testing.T) {
	have := []byte(`{"appidExclude":"example","credProtect":{"credentialProtectionPolicy":"userVerificationRequired"}}`)

	actual := &RegistrationExtensionsClientInputs{}

	require.NoError(t, json.Unmarshal(have, actual))

	assert.Equal(t, &RegistrationExtensionsClientInputs{AppIDExclude: ptr("example"), CredProtect: &RegistrationExtensionsCredProtectInputs{CredentialProtectionPolicy: ptr(UserVerificationRequired)}}, actual)

	result, err := json.Marshal(actual)
	require.NoError(t, err)

	assert.Equal(t, have, result)
}

func ptr[T any](in T) *T {
	return &in
}
