package protocol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func AssertIsProtocolError(t *testing.T, err error, errType, errDetails, errInfo string) {
	var e *Error

	require.True(t, errors.As(err, &e))

	assert.Equal(t, errType, e.Type)
	assert.Equal(t, errDetails, e.Details)
	assert.Equal(t, errInfo, e.DevInfo)
}
