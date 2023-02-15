package protocol

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func setupCollectedClientData(challenge URLEncodedBase64, origin string) *CollectedClientData {
	ccd := &CollectedClientData{
		Type:      CreateCeremony,
		Origin:    origin,
		Challenge: challenge.String(),
	}

	return ccd
}

func TestVerifyCollectedClientData(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge, "http://example.com")

	var storedChallenge = newChallenge

	if err = ccd.Verify(storedChallenge.String(), ccd.Type, []string{ccd.Origin}); err != nil {
		t.Fatalf("error verifying challenge: expected %#v got %#v", ccd.Challenge, storedChallenge)
	}
}

func TestVerifyCollectedClientDataIncorrectChallenge(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge, "http://example.com")

	bogusChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	if err = ccd.Verify(bogusChallenge.String(), ccd.Type, []string{ccd.Origin}); err == nil {
		t.Fatalf("error expected but not received. expected %#v got %#v", ccd.Challenge, bogusChallenge)
	}
}

func TestVerifyCollectedClientDataUnexpectedOrigin(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge, "http://example.com")
	storedChallenge := newChallenge
	expectedOrigins := []string{"http://different.com"}

	if err = ccd.Verify(storedChallenge.String(), ccd.Type, expectedOrigins); err == nil {
		t.Fatalf("error expected but not received. expected %#v got %#v", expectedOrigins, ccd.Origin)
	}
}

func TestVerifyCollectedClientDataWithMultipleExpectedOrigins(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge, "http://example.com")

	var storedChallenge = newChallenge

	expectedOrigins := []string{"https://exmaple.com", "9C:B4:AE:EF:05:53:6E:73:0E:C4:B8:02:E7:67:F6:7D:A4:E7:BC:26:D7:42:B5:27:FF:01:7D:68:2A:EB:FA:1D", ccd.Origin}

	if err = ccd.Verify(storedChallenge.String(), ccd.Type, expectedOrigins); err != nil {
		t.Fatalf("error verifying challenge: expected %#v got %#v", expectedOrigins, ccd.Origin)
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
