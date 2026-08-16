//go:build go1.27

package webauthn

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/protocol/webauthncose"
)

func TestCredentialParametersPQCRecommendedL3(t *testing.T) {
	params := CredentialParametersPQCRecommendedL3()

	assert.Equal(t, []protocol.CredentialParameter{
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgMLDSA44},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgMLDSA65},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgMLDSA87},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgEdDSA},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgES256},
		{Type: protocol.PublicKeyCredentialType, Algorithm: webauthncose.AlgRS256},
	}, params)
}

func TestCredentialParametersPQCRecommendedL3PrefersPostQuantum(t *testing.T) {
	postQuantum := map[webauthncose.COSEAlgorithmIdentifier]bool{
		webauthncose.AlgMLDSA44: true,
		webauthncose.AlgMLDSA65: true,
		webauthncose.AlgMLDSA87: true,
	}

	params := CredentialParametersPQCRecommendedL3()

	var classical bool

	for _, param := range params {
		assert.Equal(t, protocol.PublicKeyCredentialType, param.Type)

		if !postQuantum[param.Algorithm] {
			classical = true

			continue
		}

		assert.False(t, classical, "post-quantum algorithm %s follows a classical one", param.Algorithm)
	}

	require.True(t, classical)
	assert.Subset(t, params, CredentialParametersRecommendedL3())
}

func TestCredentialParametersPQCRecommendedL3IsVerifiable(t *testing.T) {
	for _, param := range CredentialParametersPQCRecommendedL3() {
		t.Run(param.Algorithm.String(), func(t *testing.T) {
			_, ok := webauthncose.COSESignatureAlgorithmDetails[param.Algorithm]

			assert.True(t, ok)
		})
	}
}
