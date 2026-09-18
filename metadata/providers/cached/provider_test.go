package cached

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/mock/gomock"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
	"github.com/go-webauthn/webauthn/testing/mocks"
)

func TestNew_Errors(t *testing.T) {
	testCases := []struct {
		name string
		opts []Option
		err  string
	}{
		{
			name: "ShouldFailWithoutPath",
			opts: nil,
			err:  "provider configured without setting a path for the cached file blob",
		},
		{
			name: "ShouldFailWithEmptyPath",
			opts: []Option{WithPath("")},
			err:  "provider configured without setting a path for the cached file blob",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := New(tc.opts...)
			assert.Nil(t, provider)
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestOptions(t *testing.T) {
	testCases := []struct {
		name   string
		opt    Option
		verify func(t *testing.T, p *Provider)
	}{
		{
			name: "ShouldSetPath",
			opt:  WithPath("/tmp/test.json"),
			verify: func(t *testing.T, p *Provider) {
				assert.Equal(t, "/tmp/test.json", p.name)
			},
		},
		{
			name: "ShouldSetUpdate",
			opt:  WithUpdate(false),
			verify: func(t *testing.T, p *Provider) {
				assert.False(t, p.update)
			},
		},
		{
			name: "ShouldSetUpdateTrue",
			opt:  WithUpdate(true),
			verify: func(t *testing.T, p *Provider) {
				assert.True(t, p.update)
			},
		},
		{
			name: "ShouldSetForceUpdate",
			opt:  WithForceUpdate(true),
			verify: func(t *testing.T, p *Provider) {
				assert.True(t, p.force)
			},
		},
		{
			name: "ShouldSetClient",
			opt:  WithClient(&http.Client{Timeout: 5 * time.Second}),
			verify: func(t *testing.T, p *Provider) {
				require.NotNil(t, p.client)
				assert.Equal(t, 5*time.Second, p.client.Timeout)
			},
		},
		{
			name: "ShouldSetMetadataURL",
			opt:  WithMetadataURL("https://example.com/mds"),
			verify: func(t *testing.T, p *Provider) {
				assert.Equal(t, "https://example.com/mds", p.uri)
			},
		},
		{
			name: "ShouldSetDecoder",
			opt: func() Option {
				d, _ := metadata.NewDecoder()
				return WithDecoder(d)
			}(),
			verify: func(t *testing.T, p *Provider) {
				assert.NotNil(t, p.decoder)
			},
		},
		{
			name: "ShouldSetClock",
			opt:  WithClock(&metadata.RealClock{}),
			verify: func(t *testing.T, p *Provider) {
				assert.NotNil(t, p.clock)
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{}

			err := tc.opt(p)
			require.NoError(t, err)

			tc.verify(t, p)
		})
	}
}

func TestWithMetadataURL_Invalid(t *testing.T) {
	testCases := []struct {
		name string
		uri  string
		err  string
	}{
		{
			name: "ShouldRejectInvalidURL",
			uri:  "not a valid url",
			err:  `parse "not a valid url": invalid URI for request`,
		},
		{
			name: "ShouldRejectEmptyURL",
			uri:  "",
			err:  `parse "": empty url`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{}
			err := WithMetadataURL(tc.uri)(p)
			require.EqualError(t, err, tc.err)
		})
	}
}

func TestWithNew(t *testing.T) {
	called := false

	fn := func(mds *metadata.Metadata) (metadata.Provider, error) {
		called = true
		return nil, nil
	}

	p := &Provider{}

	require.NoError(t, WithNew(fn)(p))
	require.NotNil(t, p.newup)

	_, _ = p.newup(nil)

	assert.True(t, called)
}

func TestProviderDoesNotPoisonCache(t *testing.T) {
	const sentinel = "cached blob that must survive a failed refresh"

	testCases := []struct {
		name    string
		status  int
		body    string
		wantErr string
	}{
		{
			name:    "ShouldRejectServerError",
			status:  http.StatusServiceUnavailable,
			body:    "<html>503 Service Unavailable</html>",
			wantErr: "unexpected status code 503",
		},
		{
			name:    "ShouldRejectNotFound",
			status:  http.StatusNotFound,
			body:    "not found",
			wantErr: "unexpected status code 404",
		},
		{
			// A 200 response is not enough: the body must decode and parse before it is allowed to replace the cache.
			name:    "ShouldRejectUnparseableBody",
			status:  http.StatusOK,
			body:    "this is not a jwt",
			wantErr: "token is malformed",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = w.Write([]byte(tc.body))
			}))
			defer srv.Close()

			t.Run("ShouldPreserveExistingCache", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "mds.jwt")
				require.NoError(t, os.WriteFile(path, []byte(sentinel), 0600))

				// Force skips reading the existing cache and goes straight to the download.
				_, err := New(WithPath(path), WithMetadataURL(srv.URL), WithForceUpdate(true))
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				content, err := os.ReadFile(path)
				require.NoError(t, err)
				assert.Equal(t, sentinel, string(content), "a failed refresh must not overwrite the cached blob")
			})

			t.Run("ShouldNotLeaveCacheFileBehind", func(t *testing.T) {
				path := filepath.Join(t.TempDir(), "mds.jwt")

				_, err := New(WithPath(path), WithMetadataURL(srv.URL))
				require.Error(t, err)
				assert.ErrorContains(t, err, tc.wantErr)

				_, err = os.Stat(path)
				assert.True(t, os.IsNotExist(err), "a cache file we created but never populated must be removed, otherwise it fails to parse on every subsequent run")
			})
		})
	}
}

func TestProviderExtended(t *testing.T) {
	ctx := context.Background()

	entry := &metadata.Entry{MetadataStatement: metadata.Statement{Description: "Test U2F Authenticator"}}

	t.Run("ShouldForwardToExtendedProvider", func(t *testing.T) {
		inner, err := memory.New(
			memory.WithMetadata(map[uuid.UUID]*metadata.Entry{}),
			memory.WithMetadataKeyIdentifiers(map[string]*metadata.Entry{"abcdef": entry}),
			memory.WithValidateEntryKeyIdentifier(true),
			memory.WithValidateStatusCertificateScope(true),
			memory.WithValidateAAGUID(true),
			memory.WithValidateAttestationFormats(true),
			memory.WithValidateAlgorithms(true),
			memory.WithValidateBackupEligibility(true),
			memory.WithValidateExtensions(true),
			memory.WithValidateUserVerification(true),
		)
		require.NoError(t, err)

		p := &Provider{Provider: inner}

		actual, err := p.GetEntryByKeyIdentifier(ctx, "abcdef")
		require.NoError(t, err)
		assert.Equal(t, entry, actual)

		assert.True(t, p.GetValidateEntryKeyIdentifier(ctx))
		assert.True(t, p.GetValidateStatusCertificateScope(ctx))
		assert.True(t, p.GetValidateAAGUID(ctx))
		assert.True(t, p.GetValidateAttestationFormats(ctx))
		assert.True(t, p.GetValidateAlgorithms(ctx))
		assert.True(t, p.GetValidateBackupEligibility(ctx))
		assert.True(t, p.GetValidateExtensions(ctx))
		assert.True(t, p.GetValidateUserVerification(ctx))
	})

	t.Run("ShouldNotValidateWithoutExtendedProvider", func(t *testing.T) {
		p := &Provider{Provider: mocks.NewMockMetadataProvider(gomock.NewController(t))}

		actual, err := p.GetEntryByKeyIdentifier(ctx, "abcdef")
		require.NoError(t, err)
		assert.Nil(t, actual)

		assert.False(t, p.GetValidateEntryKeyIdentifier(ctx))
		assert.False(t, p.GetValidateStatusCertificateScope(ctx))
		assert.False(t, p.GetValidateAAGUID(ctx))
		assert.False(t, p.GetValidateAttestationFormats(ctx))
		assert.False(t, p.GetValidateAlgorithms(ctx))
		assert.False(t, p.GetValidateBackupEligibility(ctx))
		assert.False(t, p.GetValidateExtensions(ctx))
		assert.False(t, p.GetValidateUserVerification(ctx))
	})
}
