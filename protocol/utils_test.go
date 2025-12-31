package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestValidateRPID(t *testing.T) {
	testCases := []struct {
		name  string
		value string
		err   string
	}{
		{
			name:  "ValidRPIDDomain",
			value: "example.com",
		},
		{
			name:  "ValidRPIDLocalHost",
			value: "localhost",
		},
		{
			name:  "ValidRPIDUsingIPv4",
			value: "127.0.0.1",
		},
		{
			name:  "ValidRPIDUsingIPv4Alt",
			value: "1.1.1.1",
		},
		{
			name:  "ValidRPIDUsingIPv6",
			value: "2001:DB8:0:0:8:800:200C:417A",
		},
		{
			name:  "ValidRPIDUsingIPv6Alt",
			value: "::1",
		},
		{
			name:  "InvalidRPIDNotDomain",
			value: "example",
			err:   "the domain component must actually be a domain",
		},
		{
			name:  "InvalidRPIDScheme",
			value: "https://example.com",
			err:   "the scheme component must be empty",
		},
		{
			name:  "InvalidRPIDPort",
			value: "example.com:1234",
			err:   "the port component must be empty",
		},
		{
			name:  "InvalidRPIDPortWithScheme",
			value: "https://example.com:1234",
			err:   "the port component must be empty",
		},
		{
			name:  "InvalidRPIDPath",
			value: "example.com/example",
			err:   "the path component must be empty",
		},
		{
			name:  "InvalidRPIDQuery",
			value: "example.com?abc=123",
			err:   "the query component must be empty",
		},
		{
			name:  "InvalidRPIDFragment",
			value: "example.com#abc=123",
			err:   "the fragment component must be empty",
		},
		{
			name:  "InvalidRPIDPathWithScheme",
			value: "https://example.com/example",
			err:   "the path component must be empty",
		},
		{
			name:  "InvalidRPIDQueryWithScheme",
			value: "https://example.com?abc=123",
			err:   "the query component must be empty",
		},
		{
			name:  "InvalidRPIDFragmentWithScheme",
			value: "https://example.com#abc=123",
			err:   "the fragment component must be empty",
		},
		{
			name:  "InvalidEmpty",
			value: "",
			err:   "empty value provided",
		},
		{
			name:  "InvalidURI",
			value: "https://example\x00.com",
			err:   "parse \"https://example\\x00.com\": net/url: invalid control character in URL",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRPID(tc.value)

			if tc.err == "" {
				assert.NoError(t, err)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}
