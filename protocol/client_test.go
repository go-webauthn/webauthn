package protocol

import (
	"net/url"
	"testing"
)

func setupCollectedClientData(challenge string) *CollectedClientData {
	return &CollectedClientData{
		Type:      CreateCeremony,
		Origin:    "example.com",
		Challenge: challenge,
	}
}

func TestVerifyCollectedClientData(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge)
	var storedChallenge = newChallenge

	originURL, _ := url.Parse(ccd.Origin)
	err = ccd.Verify(storedChallenge, ccd.Type, FullyQualifiedOrigin(originURL))
	if err != nil {
		t.Fatalf("error verifying challenge: expected %#v got %#v", ccd.Challenge, storedChallenge)
	}
}

func TestVerifyCollectedClientDataIncorrectChallenge(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}
	ccd := setupCollectedClientData(newChallenge)
	bogusChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}
	err = ccd.Verify(bogusChallenge, ccd.Type, ccd.Origin)
	if err == nil {
		t.Fatalf("error expected but not received. expected %#v got %#v", ccd.Challenge, bogusChallenge)
	}
}
