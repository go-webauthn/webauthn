//go:build go1.27

package webauthncose

import (
	"testing"
)

func TestRSARejectsMLDSAAlgorithm(t *testing.T) {
	testCases := []struct {
		name string
		alg  COSEAlgorithmIdentifier
		err  string
	}{
		{"ShouldRejectMLDSA44", AlgMLDSA44, "RSA key has unsupported algorithm ML-DSA-44"},
		{"ShouldRejectMLDSA65", AlgMLDSA65, "RSA key has unsupported algorithm ML-DSA-65"},
		{"ShouldRejectMLDSA87", AlgMLDSA87, "RSA key has unsupported algorithm ML-DSA-87"},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testRSARejectsAlgorithm(t, tc.alg, tc.err)
		})
	}
}
