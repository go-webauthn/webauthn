package protocol

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestClientCapabilities_Supported(t *testing.T) {
	reported := ClientCapabilities{
		ClientCapabilityConditionalGet:    true,
		ClientCapabilityConditionalCreate: false,
	}

	testCases := []struct {
		name             string
		have             ClientCapabilities
		capability       ClientCapability
		expectedValue    bool
		expectedReported bool
	}{
		{
			name:             "ShouldReportSupported",
			have:             reported,
			capability:       ClientCapabilityConditionalGet,
			expectedValue:    true,
			expectedReported: true,
		},
		{
			name:             "ShouldReportUnsupported",
			have:             reported,
			capability:       ClientCapabilityConditionalCreate,
			expectedValue:    false,
			expectedReported: true,
		},
		{
			name:             "ShouldNotReportAbsent",
			have:             reported,
			capability:       ClientCapabilityHybridTransport,
			expectedValue:    false,
			expectedReported: false,
		},
		{
			name:             "ShouldNotReportFromNil",
			have:             nil,
			capability:       ClientCapabilityConditionalGet,
			expectedValue:    false,
			expectedReported: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			value, ok := tc.have.Supported(tc.capability)

			assert.Equal(t, tc.expectedValue, value)
			assert.Equal(t, tc.expectedReported, ok)
		})
	}
}

func TestClientCapability_Values(t *testing.T) {
	testCases := []struct {
		name     string
		have     ClientCapability
		expected string
	}{
		{"ConditionalCreate", ClientCapabilityConditionalCreate, "conditionalCreate"},
		{"ConditionalGet", ClientCapabilityConditionalGet, "conditionalGet"},
		{"HybridTransport", ClientCapabilityHybridTransport, "hybridTransport"},
		{"PasskeyPlatformAuthenticator", ClientCapabilityPasskeyPlatformAuthenticator, "passkeyPlatformAuthenticator"},
		{"UserVerifyingPlatformAuthenticator", ClientCapabilityUserVerifyingPlatformAuthenticator, "userVerifyingPlatformAuthenticator"},
		{"RelatedOrigins", ClientCapabilityRelatedOrigins, "relatedOrigins"},
		{"SignalAllAcceptedCredentials", ClientCapabilitySignalAllAcceptedCredentials, "signalAllAcceptedCredentials"},
		{"SignalCurrentUserDetails", ClientCapabilitySignalCurrentUserDetails, "signalCurrentUserDetails"},
		{"SignalUnknownCredential", ClientCapabilitySignalUnknownCredential, "signalUnknownCredential"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, string(tc.have))
		})
	}
}

func TestExtensionClientCapability(t *testing.T) {
	testCases := []struct {
		name     string
		have     string
		expected ClientCapability
	}{
		{"ShouldPrefixIdentifier", ExtensionPRF, "extension:prf"},
		{"ShouldPrefixUnmodelledIdentifier", "futureExtension", "extension:futureExtension"},
		{"ShouldNotPrefixTwice", "extension:prf", "extension:prf"},
		{"ShouldNotBuildFromEmpty", "", ""},
		{"ShouldNotBuildFromBarePrefix", "extension:", ""},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, ExtensionClientCapability(tc.have))
		})
	}
}

func TestClientCapability_Extension(t *testing.T) {
	testCases := []struct {
		name               string
		have               ClientCapability
		expectedIdentifier string
		expectedOK         bool
	}{
		{"ShouldSplitExtensionCapability", "extension:appid", ExtensionAppID, true},
		{"ShouldSplitUnmodelledExtension", "extension:futureExtension", "futureExtension", true},
		{"ShouldNotSplitPlainCapability", ClientCapabilityConditionalGet, "", false},
		{"ShouldNotSplitBarePrefix", "extension:", "", false},
		{"ShouldNotSplitEmpty", "", "", false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			identifier, ok := tc.have.Extension()

			assert.Equal(t, tc.expectedIdentifier, identifier)
			assert.Equal(t, tc.expectedOK, ok)
		})
	}
}

func TestClientCapabilities_Extension(t *testing.T) {
	have := ClientCapabilities{
		"extension:prf":                true,
		"extension:largeBlob":          false,
		ClientCapabilityConditionalGet: true,
	}

	testCases := []struct {
		name             string
		identifier       string
		expectedValue    bool
		expectedReported bool
	}{
		{"ShouldReportSupported", ExtensionPRF, true, true},
		{"ShouldReportUnsupported", ExtensionLargeBlob, false, true},
		{"ShouldNotReportAbsent", ExtensionCredProps, false, false},
		{"ShouldAcceptAlreadyPrefixed", "extension:prf", true, true},
		{"ShouldNotReportEmptyIdentifier", "", false, false},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			value, ok := have.Extension(tc.identifier)

			assert.Equal(t, tc.expectedValue, value)
			assert.Equal(t, tc.expectedReported, ok)
		})
	}
}

func TestClientCapabilities_JSONRoundTrip(t *testing.T) {
	data := `{"conditionalGet":true,"extension:prf":true,"futureCapability":false,"signalUnknownCredential":true}`

	var capabilities ClientCapabilities

	require.NoError(t, json.Unmarshal([]byte(data), &capabilities))

	assert.Len(t, capabilities, 4)

	supported, reported := capabilities.Supported(ClientCapabilityConditionalGet)
	assert.True(t, supported)
	assert.True(t, reported)

	supported, reported = capabilities.Extension(ExtensionPRF)
	assert.True(t, supported)
	assert.True(t, reported)

	supported, reported = capabilities.Supported("futureCapability")
	assert.False(t, supported)
	assert.True(t, reported)

	encoded, err := json.Marshal(capabilities)
	require.NoError(t, err)

	assert.JSONEq(t, data, string(encoded))
}
