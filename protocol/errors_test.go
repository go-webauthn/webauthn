package protocol

import (
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestError_Copy(t *testing.T) {
	e1 := &Error{
		Type:    "test",
		Details: "This is a test",
		DevInfo: "Really, it's a test",
		Err:     errors.New("some error"),
	}

	e2 := e1.WithInfo("Diff Info")
	e3 := e1.WithDetails("Diff Details")
	e4 := e1.WithError(errors.New("some other error"))

	assert.Equal(t, "Really, it's a test", e1.DevInfo)
	assert.Equal(t, "This is a test", e1.Details)
	assert.EqualError(t, e1.Err, "some error")

	assert.Equal(t, "Diff Info", e2.DevInfo)
	assert.Equal(t, e1.Details, e2.Details)
	assert.Equal(t, e1.Err, e2.Err)

	assert.Equal(t, "Really, it's a test", e3.DevInfo)
	assert.Equal(t, "Diff Details", e3.Details)
	assert.EqualError(t, e3.Err, "some error")

	assert.Equal(t, e1.DevInfo, e3.DevInfo)
	assert.Equal(t, "Diff Details", e3.Details)
	assert.Equal(t, e1.Err, e3.Err)

	assert.Equal(t, e1.DevInfo, e4.DevInfo)
	assert.Equal(t, e1.Details, e4.Details)
	assert.EqualError(t, e4.Err, "some other error")

	assert.NotEqual(t, e1, e2)
	assert.NotEqual(t, e1, e3)
	assert.NotEqual(t, e1, e4)
	assert.NotEqual(t, e2, e3)
	assert.NotEqual(t, e2, e4)
	assert.NotEqual(t, e3, e4)

	e := e1.Unwrap()

	assert.EqualError(t, e, "some error")
	assert.EqualError(t, e1, "This is a test")
}

func TestErrorUnknownCredential_Copy(t *testing.T) {
	e1 := &ErrorUnknownCredential{
		Err: &Error{
			Type:    "test",
			Details: "This is a test",
			DevInfo: "Really, it's a test",
			Err:     errors.New("some error"),
		},
	}
	e2 := e1.WithInfo("Diff Info")
	e3 := e1.WithDetails("Diff Details")
	e4 := e1.WithError(errors.New("some other error"))

	assert.Equal(t, "Really, it's a test", e1.Err.DevInfo)
	assert.Equal(t, "This is a test", e1.Err.Details)
	assert.EqualError(t, e1.Err.Err, "some error")

	assert.Equal(t, "Diff Info", e2.Err.DevInfo)
	assert.Equal(t, e1.Err.Details, e2.Err.Details)
	assert.Equal(t, e1.Err.Err, e2.Err.Err)

	assert.Equal(t, "Really, it's a test", e3.Err.DevInfo)
	assert.Equal(t, "Diff Details", e3.Err.Details)
	assert.EqualError(t, e3.Err.Err, "some error")

	assert.Equal(t, e1.Err.DevInfo, e3.Err.DevInfo)
	assert.Equal(t, "Diff Details", e3.Err.Details)
	assert.Equal(t, e1.Err.Err, e3.Err.Err)

	assert.Equal(t, e1.Err.DevInfo, e4.Err.DevInfo)
	assert.Equal(t, e1.Err.Details, e4.Err.Details)
	assert.EqualError(t, e4.Err.Err, "some other error")

	assert.NotEqual(t, e1, e2)
	assert.NotEqual(t, e1, e3)
	assert.NotEqual(t, e1, e4)
	assert.NotEqual(t, e2, e3)
	assert.NotEqual(t, e2, e4)
	assert.NotEqual(t, e3, e4)

	e := e1.Unwrap()

	assert.Equal(t, e1.Err, e)
	assert.EqualError(t, e1, "This is a test")
}
