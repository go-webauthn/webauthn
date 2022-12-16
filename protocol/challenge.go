package protocol

import (
	"crypto/rand"
)

// ChallengeLength - Length of bytes to generate for a challenge
const ChallengeLength = 32

// Create a new challenge that should be signed and returned by the authenticator.
// The spec recommends using at least 16 bytes with 100 bits of entropy. We use 32 bytes.
func CreateChallenge() (URLEncodedBase64, error) {
	challenge := make([]byte, ChallengeLength)
	_, err := rand.Read(challenge)
	if err != nil {
		return nil, err
	}
	return URLEncodedBase64(challenge), nil
}
