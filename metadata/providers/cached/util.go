package cached

import (
	"os"
	"path/filepath"

	"github.com/go-webauthn/webauthn/metadata"
	"github.com/go-webauthn/webauthn/metadata/providers/memory"
)

// doAtomicReplace writes the data to a temporary file in the same directory as the cache before atomically replacing
// it. The existing cache is never truncated or otherwise modified until the replacement has been written and synced in
// full, so neither a partial write nor a failure part way through can leave a corrupt blob behind. The temporary file
// is removed if any step fails.
func doAtomicReplace(name string, data []byte) (err error) {
	var f *os.File

	if f, err = os.CreateTemp(filepath.Dir(name), filepath.Base(name)+".tmp*"); err != nil {
		return err
	}

	tmp := f.Name()

	defer func() {
		if err != nil {
			_ = os.Remove(tmp)
		}
	}()

	if _, err = f.Write(data); err != nil {
		_ = f.Close()

		return err
	}

	if err = f.Sync(); err != nil {
		_ = f.Close()

		return err
	}

	if err = f.Close(); err != nil {
		return err
	}

	return os.Rename(tmp, name)
}

func defaultNew(mds *metadata.Metadata) (provider metadata.Provider, err error) {
	return memory.New(
		memory.WithMetadata(mds.ToMap()),
		memory.WithValidateEntry(true),
		memory.WithValidateEntryPermitZeroAAGUID(false),
		memory.WithValidateTrustAnchor(true),
		memory.WithValidateStatus(true),
	)
}
