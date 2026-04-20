package protocol

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestVerifyCollectedClientData(t *testing.T) {
	testCases := []struct {
		name            string
		origin          string
		topOrigin       string
		crossOrigin     bool
		rpOrigins       []string
		rpTopOrigins    []string
		topOriginMode   TopOriginVerificationMode
		allowCrossOrign bool
		ceremony        CeremonyType
		err             string
		errType         string
		errDetails      string
		errInfo         string
	}{
		{
			name:            "ShouldSucceed",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			topOriginMode:   TopOriginExplicitVerificationMode,
			allowCrossOrign: true,
		},
		{
			name:            "ShouldSucceedNoTopOrigin",
			origin:          "http://example.com",
			crossOrigin:     true,
			topOriginMode:   TopOriginExplicitVerificationMode,
			allowCrossOrign: true,
		},
		{
			name:            "ShouldSucceedTopOriginDifferentFromOrigin",
			origin:          "http://example.com",
			topOrigin:       "http://example2.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			topOriginMode:   TopOriginExplicitVerificationMode,
		},
		{
			name:            "ShouldFailTopOriginMismatch",
			origin:          "http://example.com",
			topOrigin:       "http://example2.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			rpTopOrigins:    []string{"https://example3.com"},
			topOriginMode:   TopOriginExplicitVerificationMode,
			err:             "Error validating top origin",
		},
		{
			name:            "ShouldSucceedTopOriginImplicit",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			topOriginMode:   TopOriginImplicitVerificationMode,
		},
		{
			name:            "ShouldSucceedTopOriginAuto",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			rpTopOrigins:    []string{"https://example.com"},
			topOriginMode:   TopOriginAutoVerificationMode,
		},
		{
			name:            "ShouldSucceedMultipleExpectedOrigins",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			rpOrigins:       []string{"https://exmaple.com", "9C:B4:AE:EF:05:53:6E:73:0E:C4:B8:02:E7:67:F6:7D:A4:E7:BC:26:D7:42:B5:27:FF:01:7D:68:2A:EB:FA:1D", "http://example.com"},
			topOriginMode:   TopOriginExplicitVerificationMode,
		},
		{
			name:            "ShouldFailTopOriginInvalidMode",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			rpTopOrigins:    []string{"https://example.com"},
			topOriginMode:   -1,
			errType:         "not_implemented",
			errDetails:      "Error handling unknown Top Origin verification mode",
		},
		{
			name:            "ShouldFailCrossOriginNotAllowed",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			allowCrossOrign: false,
			topOriginMode:   TopOriginExplicitVerificationMode,
			errType:         "verification_error",
			errDetails:      "Error validating cross origin flag",
			errInfo:         "The cross origin flag is invalid due to the configuration.",
		},
		{
			name:            "ShouldFailUnexpectedOrigin",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			rpOrigins:       []string{"http://different.com"},
			topOriginMode:   TopOriginExplicitVerificationMode,
			errType:         "verification_error",
			errDetails:      "Error validating origin",
			errInfo:         "Expected Values: [http://different.com], Received: http://example.com",
		},
		{
			name:          "ShouldFailTopOriginWithoutCrossOrigin",
			origin:        "http://example.com",
			topOrigin:     "http://example2.com",
			crossOrigin:   false,
			topOriginMode: TopOriginExplicitVerificationMode,
			errType:       "verification_error",
			errDetails:    "Error validating topOrigin",
			errInfo:       "The topOrigin can't have values unless crossOrigin is true.",
		},
		{
			name:            "ShouldFailUnexpectedTopOrigin",
			origin:          "http://example.com",
			topOrigin:       "http://example.com",
			crossOrigin:     true,
			allowCrossOrign: true,
			rpOrigins:       []string{"http://example.com"},
			rpTopOrigins:    []string{"http://different.com"},
			topOriginMode:   TopOriginExplicitVerificationMode,
			err:             "Error validating top origin",
		},
		{
			name:          "ShouldFailCeremonyMismatch",
			origin:        "http://example.com",
			crossOrigin:   false,
			topOriginMode: TopOriginExplicitVerificationMode,
			ceremony:      AssertCeremony,
			errType:       "verification_error",
			errDetails:    "Error validating ceremony type",
			errInfo:       fmt.Sprintf("Expected Value: %s, Received: %s", AssertCeremony, CreateCeremony),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			challenge, err := CreateChallenge()
			require.NoError(t, err)

			ccd := setupCollectedClientData(challenge, tc.origin, tc.topOrigin, tc.crossOrigin)

			rpOrigins := tc.rpOrigins
			if rpOrigins == nil {
				rpOrigins = []string{ccd.Origin}
			}

			rpTopOrigins := tc.rpTopOrigins
			if rpTopOrigins == nil {
				rpTopOrigins = []string{ccd.TopOrigin}
			}

			ceremony := tc.ceremony
			if ceremony == "" {
				ceremony = ccd.Type
			}

			err = ccd.Verify(challenge.String(), ceremony, rpOrigins, rpTopOrigins, tc.topOriginMode, tc.allowCrossOrign)

			switch {
			case tc.err != "":
				assert.EqualError(t, err, tc.err)
			case tc.errType != "":
				AssertIsProtocolError(t, err, tc.errType, tc.errDetails, tc.errInfo)
			default:
				assert.NoError(t, err)
			}
		})
	}
}

func TestVerifyCollectedClientData_IncorrectChallenge(t *testing.T) {
	challenge, err := CreateChallenge()
	require.NoError(t, err)

	ccd := setupCollectedClientData(challenge, "http://example.com", "http://example.com", true)

	bogusChallenge, err := CreateChallenge()
	require.NoError(t, err)

	AssertIsProtocolError(t, ccd.Verify(bogusChallenge.String(), ccd.Type, []string{ccd.Origin}, []string{ccd.TopOrigin}, TopOriginExplicitVerificationMode, true), "verification_error", "Error validating challenge", fmt.Sprintf("Expected b Value: \"%s\"\nReceived b: \"%s\"\n", bogusChallenge.String(), challenge.String()))
}

func TestVerifyCollectedClientData_TokenBinding(t *testing.T) {
	testCases := []struct {
		name         string
		tokenBinding *TokenBinding
		err          string
	}{
		{
			name:         "ShouldSucceedWithNilTokenBinding",
			tokenBinding: nil,
		},
		{
			name:         "ShouldSucceedWithPresentStatus",
			tokenBinding: &TokenBinding{Status: Present, ID: "abc"},
		},
		{
			name:         "ShouldSucceedWithSupportedStatus",
			tokenBinding: &TokenBinding{Status: Supported},
		},
		{
			name:         "ShouldSucceedWithNotSupportedStatus",
			tokenBinding: &TokenBinding{Status: NotSupported},
		},
		{
			name:         "ShouldFailWithEmptyStatus",
			tokenBinding: &TokenBinding{},
			err:          "Error decoding clientData, token binding present without status",
		},
		{
			name:         "ShouldFailWithInvalidStatus",
			tokenBinding: &TokenBinding{Status: "invalid-status"},
			err:          "Error decoding clientData, token binding present with invalid status",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			newChallenge, err := CreateChallenge()
			require.NoError(t, err)

			ccd := setupCollectedClientData(newChallenge, "http://example.com", "", false)
			ccd.TokenBinding = tc.tokenBinding

			err = ccd.Verify(newChallenge.String(), CreateCeremony, []string{ccd.Origin}, nil, TopOriginExplicitVerificationMode, false)
			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestFullyQualifiedOrigin(t *testing.T) {
	testCases := []struct {
		name                  string
		have                  string
		expected, expectedErr string
	}{
		{"ShouldParse", "https://app.example.com", "https://app.example.com", ``},
		{"ShouldParseWithPath", "https://app.example.com/apath", "https://app.example.com", ``},
		{"ShouldParseWithPort", "https://app.example.com:8443/apath", "https://app.example.com:8443", ``},
		{"ShouldParseWithCredentials", "https://user:password@app.example.com/", "https://app.example.com", ``},
		{"ShouldParseWithQuery", "https://app.example.com/?abc=123", "https://app.example.com", ``},
		{"ShouldParseWithFragment", "https://app.example.com/#abc", "https://app.example.com", ``},
		{"ShouldSkipParsingAndroidNative", "android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0", "android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0", ""},
		{"ShouldFailToParseMissingScheme", "app.example.com/apath", "", `parse "app.example.com/apath": invalid URI for request`},
		{"ShouldFailToParseBlankScheme", "://app.example.com/apath", "", `parse "://app.example.com/apath": missing protocol scheme`},
		{"ShouldFailToParseMissingHost", "https:///apath", "", `url 'https:///apath' does not have a host`},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual, actualErr := FullyQualifiedOrigin(tc.have)

			assert.Equal(t, tc.expected, actual)

			if tc.expectedErr == "" {
				assert.NoError(t, actualErr)
			} else {
				assert.EqualError(t, actualErr, tc.expectedErr)
			}
		})
	}
}

func TestIsOriginInHaystack(t *testing.T) {
	testCases := []struct {
		name     string
		origin   string
		haystack []string
		expected bool
	}{
		{
			"ShouldHandleFullyQualifiedOrigin",
			"https://app.example.com",
			[]string{"https://app.example.com"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginCaseInsensitiveScheme",
			"https://app.example.com",
			[]string{"HTTPS://app.example.com"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginCaseInsensitiveHost",
			"https://app.EXAMPLE.com",
			[]string{"https://app.example.com"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginWithPort",
			"https://app.example.com:443",
			[]string{"https://app.example.com:443"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentScheme",
			"http://app.example.com",
			[]string{"https://app.example.com"},
			false,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentPort",
			"https://app.example.com:443",
			[]string{"https://app.example.com"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentPortNotMatchingScheme",
			"https://app.example.com:80",
			[]string{"https://app.example.com"},
			false,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentPath",
			"https://app.example.com/abc",
			[]string{"https://app.example.com"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentQuery",
			"https://app.example.com/?abc=123",
			[]string{"https://app.example.com"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentQueryCount",
			"https://app.example.com/?abc=123",
			[]string{"https://app.example.com/?zyz=123&abc=123"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentQueryOrder",
			"https://app.example.com/?abc=123&xyz=123",
			[]string{"https://app.example.com/?xyz=123&abc=123"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDifferentQueryValue",
			"https://app.example.com/?abc=123&xyz=123",
			[]string{"https://app.example.com/?xyz=1234&abc=123"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginFragment",
			"https://app.example.com/#abc",
			[]string{"https://app.example.com/#abc"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginFragmentDifferent",
			"https://app.example.com/#abc",
			[]string{"https://app.example.com/#abc2"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginWithoutAllowed",
			"https://app.example.com",
			nil,
			false,
		},
		{
			"ShouldHandleFullyQualifiedOriginWithTrailingSlashes",
			"https://app.example.com/",
			[]string{"https://app.example.com"},
			true,
		},
		{
			"ShouldHandleNativeAppAndroid",
			"android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0",
			[]string{"android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0"},
			true,
		},
		{
			"ShouldHandleNativeAppAndroidCaseSensitive",
			"android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69F0",
			[]string{"android:apk-key-hash:7d1043473d55bfa90e8530d35801d4e381bc69f0"},
			false,
		},
		{
			"ShouldHandleNonFQDNOrigin",
			"https://user:password@app.example.com/",
			[]string{"https://app.example.com/"},
			true,
		},
		{
			"ShouldHandleNonFQDNOriginExactStringMatch",
			"https://user:password@app.example.com/",
			[]string{"https://user:password@app.example.com/"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDefaultPortEquivalentHTTPS",
			"https://app.example.com:443",
			[]string{"https://app.example.com"},
			true,
		},
		{
			"ShouldHandleFullyQualifiedOriginDefaultPortEquivalentHTTP",
			"http://app.example.com:80",
			[]string{"http://app.example.com"},
			true,
		},
		{
			"ShouldHandleInvalidURLAsSimpleStringMatch",
			"http://app.example.%%%&123?1",
			[]string{"http://app.example.%%%&123?1"},
			true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.expected, IsOriginInHaystack(tc.origin, tc.haystack))
		})
	}
}

func setupCollectedClientData(challenge URLEncodedBase64, origin, topOrigin string, crossOrigin bool) *CollectedClientData {
	ccd := &CollectedClientData{
		Type:        CreateCeremony,
		Origin:      origin,
		TopOrigin:   topOrigin,
		CrossOrigin: crossOrigin,
		Challenge:   challenge.String(),
	}

	return ccd
}
