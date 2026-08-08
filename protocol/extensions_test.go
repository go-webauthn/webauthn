package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestExtensionInputsIsZero(t *testing.T) {
	testCases := []struct {
		name     string
		have     interface{ IsZero() bool }
		expected bool
	}{
		{"PRFValuesZero", PRFValues{}, true},
		{"PRFValuesFirst", PRFValues{First: []byte("a")}, false},
		{"PRFValuesSecond", PRFValues{Second: []byte("a")}, false},
		{"PRFInputsZero", PRFInputs{}, true},
		{"PRFInputsEval", PRFInputs{Eval: PRFValues{First: []byte("a")}}, false},
		{"PRFInputsByCredential", PRFInputs{EvalByCredential: map[string]PRFValues{"a": {}}}, false},
		{"LargeBlobInputsZero", LargeBlobInputs{}, true},
		{"LargeBlobInputsSupport", LargeBlobInputs{Support: LargeBlobSupportRequired}, false},
		{"LargeBlobInputsRead", LargeBlobInputs{Read: true}, false},
		{"LargeBlobInputsWrite", LargeBlobInputs{Write: []byte("a")}, false},
		{"HMACGetSecretInputsZero", HMACGetSecretInputs{}, true},
		{"HMACGetSecretInputsSalt1", HMACGetSecretInputs{Salt1: []byte("a")}, false},
		{"HMACGetSecretInputsSalt2", HMACGetSecretInputs{Salt2: []byte("a")}, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, tc.have.IsZero())
		})
	}
}

func TestPtr(t *testing.T) {
	value := ptr(true)

	assert.NotNil(t, value)
	assert.True(t, *value)

	number := ptr(uint(4))

	assert.Equal(t, uint(4), *number)
}
