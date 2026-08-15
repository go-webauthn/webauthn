package webauthn

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/protocol"
)

func TestWebAuthnRelatedOrigins(t *testing.T) {
	t.Run("ShouldBuildTheDocumentFromTheConfiguredOrigins", func(t *testing.T) {
		w, err := New(&Config{
			RPID:          "example.com",
			RPDisplayName: "Test Display Name",
			RPOrigins:     []string{"https://example.com", "https://example.com.au"},
		})
		require.NoError(t, err)

		related, err := w.RelatedOrigins()

		require.NoError(t, err)
		require.NotNil(t, related)
		assert.Equal(t, []string{"https://example.com", "https://example.com.au"}, related.Origins)

		data, err := related.Bytes()

		require.NoError(t, err)
		assert.Equal(t, `{"origins":["https://example.com","https://example.com.au"]}`, string(data))
	})

	t.Run("ShouldNormalizeTheConfiguredOrigins", func(t *testing.T) {
		w, err := New(&Config{
			RPID:          "example.com",
			RPDisplayName: "Test Display Name",
			RPOrigins:     []string{"https://example.com:443", "https://example.com/"},
		})
		require.NoError(t, err)

		related, err := w.RelatedOrigins()

		require.NoError(t, err)
		assert.Equal(t, []string{"https://example.com"}, related.Origins)
	})

	t.Run("ShouldServeTheDocumentAtTheWellKnownPath", func(t *testing.T) {
		w, err := New(&Config{
			RPID:          "example.com",
			RPDisplayName: "Test Display Name",
			RPOrigins:     []string{"https://example.com"},
		})
		require.NoError(t, err)

		related, err := w.RelatedOrigins()
		require.NoError(t, err)

		mux := http.NewServeMux()
		mux.Handle(protocol.WellKnownPathWebAuthn, related)

		recorder := httptest.NewRecorder()

		mux.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, protocol.WellKnownPathWebAuthn, nil))

		assert.Equal(t, http.StatusOK, recorder.Code)
		assert.Equal(t, "application/json", recorder.Header().Get("Content-Type"))
		assert.Equal(t, `{"origins":["https://example.com"]}`, recorder.Body.String())
	})

	t.Run("ShouldErrorWhenTheConfiguredOriginsExceedTheLabelLimit", func(t *testing.T) {
		w, err := New(&Config{
			RPID:          "example.com",
			RPDisplayName: "Test Display Name",
			RPOrigins: []string{
				"https://a.com", "https://b.com", "https://c.com",
				"https://d.com", "https://e.com", "https://f.com",
			},
		})
		require.NoError(t, err)

		related, err := w.RelatedOrigins()

		assert.Nil(t, related)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "6 distinct registrable domain labels")
	})
}
