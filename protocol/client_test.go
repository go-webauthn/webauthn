package protocol

import (
	"testing"
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

	err = ccd.Verify(storedChallenge.String(), ccd.Type, []string{ccd.Origin})
	if err != nil {
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

	err = ccd.Verify(bogusChallenge.String(), ccd.Type, []string{ccd.Origin})
	if err == nil {
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
	err = ccd.Verify(storedChallenge.String(), ccd.Type, expectedOrigins)
	if err == nil {
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
	err = ccd.Verify(storedChallenge.String(), ccd.Type, expectedOrigins)
	if err != nil {
		t.Fatalf("error verifying challenge: expected %#v got %#v", expectedOrigins, ccd.Origin)
	}
}
