package oci

import (
	"fmt"
	"os"
	"path/filepath"
)

// GCOptions configures garbage collection behavior.
type GCOptions struct {
	// ReferencedDigests is the set of digests that should be kept.
	// Any blob or extracted directory not in this set will be removed.
	ReferencedDigests []string
	// DryRun reports what would be removed without actually deleting.
	DryRun bool
}

// GCResult summarizes what garbage collection removed (or would remove).
type GCResult struct {
	RemovedBlobs   []string
	RemovedDirs    []string
	BytesReclaimed int64
}

// GC removes blobs and extracted directories that are not referenced.
func (s *Store) GC(opts GCOptions) (*GCResult, error) {
	referenced := make(map[string]bool, len(opts.ReferencedDigests))
	for _, d := range opts.ReferencedDigests {
		referenced[digestHex(d)] = true
	}

	result := &GCResult{}

	// Collect unreferenced blobs.
	blobRoot := filepath.Join(s.cacheDir, "sha256")
	if err := s.gcWalk(blobRoot, referenced, opts.DryRun, result, true); err != nil {
		return result, fmt.Errorf("gc blobs: %w", err)
	}

	// Collect unreferenced extracted directories.
	extractRoot := filepath.Join(s.cacheDir, "extracted")
	if err := s.gcWalk(extractRoot, referenced, opts.DryRun, result, false); err != nil {
		return result, fmt.Errorf("gc extracted: %w", err)
	}

	return result, nil
}

// gcWalk walks a sharded directory structure (<root>/<shard>/<hex>) and removes
// entries not in the referenced set.
func (s *Store) gcWalk(root string, referenced map[string]bool, dryRun bool, result *GCResult, isBlob bool) error {
	shards, err := os.ReadDir(root)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return err
	}

	for _, shard := range shards {
		if !shard.IsDir() {
			continue
		}

		shardPath := filepath.Join(root, shard.Name())
		entries, err := os.ReadDir(shardPath)
		if err != nil {
			return err
		}

		for _, entry := range entries {
			hex := entry.Name()
			if referenced[hex] {
				continue
			}

			entryPath := filepath.Join(shardPath, hex)

			// Compute size before removing.
			size, _ := dirSize(entryPath)

			if !dryRun {
				if err := os.RemoveAll(entryPath); err != nil {
					return fmt.Errorf("removing %s: %w", entryPath, err)
				}
			}

			result.BytesReclaimed += size
			if isBlob {
				result.RemovedBlobs = append(result.RemovedBlobs, hex)
			} else {
				result.RemovedDirs = append(result.RemovedDirs, hex)
			}
		}

		// Remove empty shard directories.
		if !dryRun {
			remaining, _ := os.ReadDir(shardPath)
			if len(remaining) == 0 {
				_ = os.Remove(shardPath)
			}
		}
	}

	return nil
}

// dirSize returns the total size of a file or directory tree.
func dirSize(path string) (int64, error) {
	var total int64
	err := filepath.Walk(path, func(_ string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if !info.IsDir() {
			total += info.Size()
		}
		return nil
	})
	return total, err
}
