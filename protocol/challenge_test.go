package protocol

import (
	"encoding/base64"
	"testing"
)

func TestCreateChallenge(t *testing.T) {
	got, err := CreateChallenge()
	if err != nil {
		t.Errorf("CreateChallenge() error = %v, wantErr %v", err, false)
		return
	}

	decoded, err := base64.RawURLEncoding.DecodeString(got)
	if err != nil {
		t.Errorf("decode base64 encoded challenge, error = %v, wantErr %v", err, false)
		return
	}

	if len(decoded) != ChallengeLength {
		t.Errorf("invalid challenge length, len = %d, want = %d", len(decoded), ChallengeLength)
	}
}
