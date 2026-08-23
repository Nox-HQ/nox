// Package fsutil holds small filesystem helpers shared across nox's on-disk
// stores.
package fsutil

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"time"
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
	if err := renameOverwrite(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("renaming into place: %w", err)
	}
	return nil
}

// renameRetries and renameRetryDelay bound the wait for a transient Windows
// sharing violation. Ten attempts over ~50ms is far longer than a concurrent
// writer holds the target, and short enough that a genuine permission error
// still surfaces promptly.
const (
	renameRetries    = 10
	renameRetryDelay = 5 * time.Millisecond
)

// renameOverwrite renames tmp over path, retrying briefly on Windows.
//
// On POSIX, rename over an existing file is atomic and cannot fail because a
// reader has it open, so the first attempt always succeeds and the loop costs
// nothing. Windows maps rename to MoveFileEx, which fails with a sharing
// violation while any other handle to the destination is open — so two
// goroutines writing the same store raced and one returned "Access is denied".
//
// That made AtomicWriteFile, which backs the baseline, cache, MCP pin and drift
// stores, unreliable under concurrency on Windows only: the very property the
// unique temp names were introduced to guarantee. The contention is transient,
// so a bounded retry is the fix; a failure that persists past it is real and is
// returned.
func renameOverwrite(tmp, path string) error {
	var err error
	for attempt := 0; attempt < renameRetries; attempt++ {
		if err = os.Rename(tmp, path); err == nil {
			return nil
		}
		if !errors.Is(err, fs.ErrPermission) && !isSharingViolation(err) {
			return err
		}
		time.Sleep(renameRetryDelay)
	}
	return err
}

// isSharingViolation reports whether err is Windows' "the process cannot access
// the file because it is being used by another process", which surfaces as a
// plain syscall errno rather than one of the fs sentinel errors.
func isSharingViolation(err error) bool {
	var errno syscall.Errno
	if !errors.As(err, &errno) {
		return false
	}
	// 5 = ERROR_ACCESS_DENIED, 32 = ERROR_SHARING_VIOLATION. Named numerically
	// because the constants live in the windows-only syscall package.
	return errno == 5 || errno == 32
}
