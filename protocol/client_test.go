package protocol

import (
	"encoding/base64"
	"testing"
)

func setupCollectedClientData(challenge []byte) *CollectedClientData {
	ccd := &CollectedClientData{
		Type:   CreateCeremony,
		Origin: "example.com",
	}

	ccd.Challenge = base64.RawURLEncoding.EncodeToString(challenge)
	return ccd
}

func TestVerifyCollectedClientData(t *testing.T) {
	newChallenge, err := CreateChallenge()
	if err != nil {
		t.Fatalf("error creating challenge: %s", err)
	}

	ccd := setupCollectedClientData(newChallenge)
	var storedChallenge = newChallenge

	err = ccd.Verify(storedChallenge.String(), ccd.Type, []string{ccd.Origin})
	if err != nil {
		t.Fatalf("error verifying challenge: expected %#v got %#v", Challenge(ccd.Challenge), storedChallenge)
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

	err = ccd.Verify(bogusChallenge.String(), ccd.Type, []string{ccd.Origin})
	if err == nil {
		t.Fatalf("error expected but not received. expected %#v got %#v", Challenge(ccd.Challenge), bogusChallenge)
	}
}
