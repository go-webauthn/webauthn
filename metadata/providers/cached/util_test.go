package cached

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
)

func TestDoOpenOrCreate(t *testing.T) {
	testCases := []struct {
		name            string
		setup           func(t *testing.T) string
		expectedCreated bool
		err             string
	}{
		{
			name: "ShouldCreateNewFile",
			setup: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "new-file.json")
			},
			expectedCreated: true,
		},
		{
			name: "ShouldOpenExistingFile",
			setup: func(t *testing.T) string {
				t.Helper()

				path := filepath.Join(t.TempDir(), "existing-file.json")

				f, err := os.Create(path)
				require.NoError(t, err)
				require.NoError(t, f.Close())

				return path
			},
			expectedCreated: false,
		},
		{
			name: "ShouldFailInvalidPath",
			setup: func(t *testing.T) string {
				t.Helper()

				return filepath.Join(t.TempDir(), "nonexistent-dir", "subdir", "file.json")
			},
			err: "no such file or directory",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := tc.setup(t)

			f, created, err := doOpenOrCreate(path)

			if tc.err != "" {
				assert.Nil(t, f)
				require.Error(t, err)
				assert.Contains(t, err.Error(), tc.err)
			} else {
				require.NoError(t, err)
				require.NotNil(t, f)
				assert.Equal(t, tc.expectedCreated, created)

				require.NoError(t, f.Close())
			}
		})
	}
}

func TestDoTruncateCopyAndSeekStart(t *testing.T) {
	testCases := []struct {
		name            string
		initialContent  string
		copyContent     string
		expectedContent string
		err             string
	}{
		{
			name:            "ShouldTruncateAndCopy",
			initialContent:  "old content that should be replaced",
			copyContent:     "new data",
			expectedContent: "new data",
		},
		{
			name:            "ShouldHandleEmptyInitialContent",
			initialContent:  "",
			copyContent:     "fresh content",
			expectedContent: "fresh content",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "test-file.json")

			f, err := os.Create(path)
			require.NoError(t, err)

			_, err = f.WriteString(tc.initialContent)
			require.NoError(t, err)

			_, err = f.Seek(0, io.SeekStart)
			require.NoError(t, err)

			rc := io.NopCloser(bytes.NewReader([]byte(tc.copyContent)))

			err = doTruncateCopyAndSeekStart(f, rc)

			if tc.err != "" {
				assert.EqualError(t, err, tc.err)
			} else {
				require.NoError(t, err)

				content, err := io.ReadAll(f)
				require.NoError(t, err)
				assert.Equal(t, tc.expectedContent, string(content))
			}

			require.NoError(t, f.Close())
		})
	}
}

func TestDefaultNew(t *testing.T) {
	testCases := []struct {
		name string
		have *metadata.Metadata
		err  string
	}{
		{
			name: "ShouldSucceedWithEmptyMetadata",
			have: &metadata.Metadata{
				Parsed: metadata.Parsed{
					NextUpdate: time.Now().Add(time.Hour * 24),
				},
			},
		},
		{
			name: "ShouldSucceedWithEntries",
			have: &metadata.Metadata{
				Parsed: metadata.Parsed{
					NextUpdate: time.Now().Add(time.Hour * 24),
					Entries: []metadata.Entry{
						{
							AaGUID: uuid.MustParse("2369d4d0-13ce-48cb-9f26-f7ed8c9a6068"),
						},
					},
				},
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			provider, err := defaultNew(tc.have)

			if tc.err == "" {
				assert.NoError(t, err)
				assert.NotNil(t, provider)
			} else {
				assert.EqualError(t, err, tc.err)
			}
		})
	}
}

func TestProviderOutdated(t *testing.T) {
	testCases := []struct {
		name     string
		have     struct {
			update  bool
			clockAt time.Time
			nextUpd time.Time
		}
		expected bool
	}{
		{
			name: "ShouldBeOutdatedWhenPastNextUpdate",
			have: struct {
				update  bool
				clockAt time.Time
				nextUpd time.Time
			}{
				update:  true,
				clockAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				nextUpd: time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC),
			},
			expected: true,
		},
		{
			name: "ShouldNotBeOutdatedWhenBeforeNextUpdate",
			have: struct {
				update  bool
				clockAt time.Time
				nextUpd time.Time
			}{
				update:  true,
				clockAt: time.Date(2025, 4, 1, 0, 0, 0, 0, time.UTC),
				nextUpd: time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC),
			},
			expected: false,
		},
		{
			name: "ShouldNotBeOutdatedWhenUpdateDisabled",
			have: struct {
				update  bool
				clockAt time.Time
				nextUpd time.Time
			}{
				update:  false,
				clockAt: time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC),
				nextUpd: time.Date(2025, 5, 1, 0, 0, 0, 0, time.UTC),
			},
			expected: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			p := &Provider{
				update: tc.have.update,
				clock:  &mockClock{now: tc.have.clockAt},
			}

			mds := &metadata.Metadata{
				Parsed: metadata.Parsed{
					NextUpdate: tc.have.nextUpd,
				},
			}

			assert.Equal(t, tc.expected, p.outdated(mds))
		})
	}
}

type mockClock struct {
	now time.Time
}

func (c *mockClock) Now() time.Time {
	return c.now
}