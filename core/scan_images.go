package core

import (
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/nox-hq/nox/core/analyzers/deps"
	"github.com/nox-hq/nox/core/image"
)

// imageReader returns the base-image reader a scan uses, or nil when image
// reading is off or the scan does not check dependencies.
func imageReader(cfg ImagesConfig, opts ScanOptions) deps.ImageReader {
	if !cfg.Enabled || !opts.Scopes.Has(ScopeDeps) {
		return nil
	}
	dir := cfg.CacheDir
	if dir == "" {
		// Without a home directory the cache is per-machine temporary
		// rather than image reading silently off.
		base := os.TempDir()
		if home, err := os.UserHomeDir(); err == nil {
			base = filepath.Join(home, ".nox", "cache")
		}
		dir = filepath.Join(base, "oci")
	}
	return &image.Client{
		HTTP:     &http.Client{Timeout: 10 * time.Minute},
		CacheDir: dir,
		Offline:  opts.Offline,
	}
}
