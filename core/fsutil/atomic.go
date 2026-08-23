// Package fsutil holds small filesystem helpers shared across nox's on-disk
// stores.
package fsutil

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

// AtomicWriteFile writes data to path atomically, creating the parent directory
// if needed.
//
// It writes to a UNIQUELY-named temp file in the same directory (os.CreateTemp)
// and renames it over the target. The unique name is what makes it
// concurrency-safe: two writers never collide on one fixed "<path>.tmp", the way
// the copies in the cache and MCP-pin stores did. The rename is atomic on POSIX,
// so a reader sees either the whole old file or the whole new one, never a
// half-written store. On any error the temp file is cleaned up.
//
// nox's data stores (baseline, cache, MCP pins, MCP drift baseline) each grew
// their own copy of this, two of them with the fixed-name, not-concurrency-safe
// variant and thinner error unwinding. A durability fix — say, adding an fsync —
// then had to be remembered in four places. Now it is one.
func AtomicWriteFile(path string, data []byte, perm fs.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return fmt.Errorf("creating directory %s: %w", dir, err)
	}

	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+"-*.tmp")
	if err != nil {
		return fmt.Errorf("creating temp file: %w", err)
	}
	tmpName := tmp.Name()

	cleanup := func() {
		if rmErr := os.Remove(tmpName); rmErr != nil && !os.IsNotExist(rmErr) {
			// Best effort: the write already failed; surfacing the remove error
			// would only obscure the original cause.
			_ = rmErr
		}
	}

	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("writing temp file: %w", err)
	}
	if err := tmp.Chmod(perm); err != nil {
		_ = tmp.Close()
		cleanup()
		return fmt.Errorf("setting permissions: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("closing temp file: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("renaming into place: %w", err)
	}
	return nil
}
