package cached

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-webauthn/webauthn/metadata"
)

func TestDoAtomicReplace(t *testing.T) {
	const original = "the cached blob that was already in place"

	t.Run("ShouldReplaceExistingCache", func(t *testing.T) {
		dir := t.TempDir()
		name := filepath.Join(dir, "mds.jwt")

		require.NoError(t, os.WriteFile(name, []byte(original), 0600))
		require.NoError(t, doAtomicReplace(name, []byte("the replacement blob")))

		content, err := os.ReadFile(name)
		require.NoError(t, err)
		assert.Equal(t, "the replacement blob", string(content))

		entries, err := os.ReadDir(dir)
		require.NoError(t, err)
		assert.Len(t, entries, 1, "the temporary file must not be left behind")
	})

	t.Run("ShouldCreateCacheWhenAbsent", func(t *testing.T) {
		dir := t.TempDir()
		name := filepath.Join(dir, "mds.jwt")

		require.NoError(t, doAtomicReplace(name, []byte("the first blob")))

		content, err := os.ReadFile(name)
		require.NoError(t, err)
		assert.Equal(t, "the first blob", string(content))
	})

	t.Run("ShouldLeaveOriginalIntactWhenReplacementFails", func(t *testing.T) {
		if os.Geteuid() == 0 {
			t.Skip("the read only directory used to force the failure is not enforced for the root user")
		}

		dir := t.TempDir()
		name := filepath.Join(dir, "mds.jwt")

		require.NoError(t, os.WriteFile(name, []byte(original), 0600))

		// Deny creation of the temporary file so the replacement cannot be written.
		require.NoError(t, os.Chmod(dir, 0500))

		t.Cleanup(func() {
			_ = os.Chmod(dir, 0700)
		})

		require.Error(t, doAtomicReplace(name, []byte("the replacement blob")))

		content, err := os.ReadFile(name)
		require.NoError(t, err)
		assert.Equal(t, original, string(content), "a failed replacement must not modify the cached blob")
	})
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
		name string
		have struct {
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
