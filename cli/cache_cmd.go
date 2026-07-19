package main

import (
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	"github.com/nox-hq/nox/core/cache"
)

func runCache(args []string) int {
	cacheFS := flag.NewFlagSet("cache", flag.ContinueOnError)
	if err := cacheFS.Parse(args); err != nil {
		return 2
	}

	if cacheFS.NArg() == 0 {
		fmt.Fprintln(os.Stderr, "Usage: nox cache <command>")
		fmt.Fprintln(os.Stderr, "Commands:")
		fmt.Fprintln(os.Stderr, "  clear   Clear the scan and registry caches")
		fmt.Fprintln(os.Stderr, "          --artifacts  ALSO delete downloaded plugin binaries")
		fmt.Fprintln(os.Stderr, "  status  Show cache statistics")
		return 2
	}

	sub := cacheFS.Arg(0)
	switch sub {
	case "clear":
		return runCacheClear(cacheFS.Args()[1:])
	case "status":
		return runCacheStatus()
	default:
		fmt.Fprintf(os.Stderr, "unknown cache command: %s\n", sub)
		return 2
	}
}

// runCacheClear clears the caches that are safe to rebuild.
//
// nox keeps three caches under ~/.nox/cache, and only one of them used to be
// cleared here:
//
//	scan       analysis results; rebuilt by the next scan
//	registry   the plugin index; re-fetched on demand
//	artifacts  DOWNLOADED PLUGIN BINARIES — see below
//
// The registry cache being unreachable was a real trap: after the index moved
// repositories, `plugin search` kept reporting stale versions while the live
// index served new ones, and `cache clear` (which only ever touched the scan
// cache, despite its name) did nothing about it. The only way out was deleting
// the directory by hand, and anyone hitting it would reasonably conclude the
// registry was broken.
//
// The artifacts cache is NOT cleared by default, and that is deliberate:
// installed plugins are executed from inside it — state.json records a
// binary_path pointing there — so removing it does not merely force a
// re-download, it breaks every installed plugin until each is reinstalled.
// It is available behind --artifacts, which says so.
func runCacheClear(args []string) int {
	clearFS := flag.NewFlagSet("cache clear", flag.ContinueOnError)
	var artifacts bool
	clearFS.BoolVar(&artifacts, "artifacts", false,
		"also delete downloaded plugin binaries (breaks installed plugins until reinstalled)")
	if err := clearFS.Parse(args); err != nil {
		return 2
	}

	rc := 0

	c := cache.New()
	if err := c.Clear(); err != nil {
		fmt.Fprintf(os.Stderr, "error: clearing scan cache: %v\n", err)
		rc = 2
	} else {
		fmt.Println("scan cache cleared")
	}

	if err := removeCacheDir("registry"); err != nil {
		fmt.Fprintf(os.Stderr, "error: clearing registry cache: %v\n", err)
		rc = 2
	} else {
		fmt.Println("registry cache cleared")
	}

	if artifacts {
		if err := removeCacheDir("artifacts"); err != nil {
			fmt.Fprintf(os.Stderr, "error: clearing artifact cache: %v\n", err)
			rc = 2
		} else {
			fmt.Println("artifact cache cleared")
			fmt.Fprintln(os.Stderr,
				"warning: installed plugins ran from this cache and are now unavailable — "+
					"reinstall them with `nox plugin install <name>`")
		}
	}

	return rc
}

// removeCacheDir deletes one directory under ~/.nox/cache. A missing directory
// is success: "clear" describes the end state, not the act.
func removeCacheDir(name string) error {
	dir := filepath.Join(noxHome(), "cache", name)
	if err := os.RemoveAll(dir); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func runCacheStatus() int {
	c := cache.New()
	if err := c.Load(); err != nil {
		fmt.Fprintf(os.Stderr, "error: loading cache: %v\n", err)
		return 2
	}

	entries, sizeBytes := c.Stats()
	fmt.Printf("scan cache entries: %d\n", entries)
	if sizeBytes > 0 {
		fmt.Printf("scan cache size: %s\n", formatBytes(sizeBytes))
	} else {
		fmt.Printf("scan cache size: 0 B\n")
	}

	// Report the other two as well: their absence from `status` is why the
	// stale-registry trap was hard to diagnose.
	for _, name := range []string{"registry", "artifacts"} {
		size, err := dirSize(filepath.Join(noxHome(), "cache", name))
		if err != nil {
			continue
		}
		fmt.Printf("%s cache size: %s\n", name, formatBytes(size))
	}
	return 0
}

// dirSize totals a directory, returning 0 when it does not exist.
func dirSize(dir string) (int64, error) {
	var total int64
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // unreadable entries are not worth failing `status` over
		}
		if d.IsDir() {
			return nil
		}
		if info, err := d.Info(); err == nil {
			total += info.Size()
		}
		return nil
	})
	if err != nil && !os.IsNotExist(err) {
		return 0, err
	}
	return total, nil
}

func formatBytes(b int64) string {
	const unit = 1024
	if b < unit {
		return fmt.Sprintf("%d B", b)
	}
	div, exp := int64(unit), 0
	for n := b / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(b)/float64(div), "KMGTPE"[exp])
}
