package oci

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// ArtifactFormat identifies the packaging format of an artifact blob.
type ArtifactFormat int

const (
	// FormatRawBinary is a single executable binary.
	FormatRawBinary ArtifactFormat = iota
	// FormatTarGz is a gzip-compressed tar archive.
	FormatTarGz
)

// ErrPathTraversal indicates a tar entry attempted to escape the destination directory.
var ErrPathTraversal = errors.New("tar entry contains path traversal")

const (
	// defaultMaxExtractSize caps the total uncompressed bytes written across all
	// entries during extraction. download() bounds the compressed blob at 500 MB,
	// but gzip's ~1000x worst-case ratio means an archive within that limit could
	// still expand to hundreds of GB and exhaust disk (a decompression bomb).
	// 2 GB comfortably fits any legitimate plugin (binaries + libraries + assets)
	// while capping the worst case to a bounded, recoverable amount of disk.
	defaultMaxExtractSize int64 = 2 * 1024 * 1024 * 1024 // 2 GB

	// defaultMaxExtractEntries caps the number of tar entries processed. This
	// bounds a "many tiny files" bomb, where per-entry filesystem overhead
	// (inodes, directory writes) dominates over the raw byte budget. A real
	// plugin has far fewer entries than this.
	defaultMaxExtractEntries = 100000
)

// gzipMagic is the two-byte magic number for gzip files.
var gzipMagic = []byte{0x1f, 0x8b}

// DetectFormat inspects the first bytes of a file to determine its format.
func DetectFormat(path string) (ArtifactFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening file for format detection: %w", err)
	}
	defer func() { _ = f.Close() }()

	header := make([]byte, 2)
	n, err := f.Read(header)
	if err != nil {
		return 0, fmt.Errorf("reading file header: %w", err)
	}
	if n >= 2 && header[0] == gzipMagic[0] && header[1] == gzipMagic[1] {
		return FormatTarGz, nil
	}
	return FormatRawBinary, nil
}

// ExtractTarGz extracts a gzip-compressed tar archive to dstDir using atomic
// extraction (extract to temp dir, then rename). Returns the list of extracted
// file paths relative to dstDir.
//
// Extraction is bounded: the total uncompressed size and the number of entries
// are capped (see defaultMaxExtractSize / defaultMaxExtractEntries) to defend
// against decompression bombs. ErrSizeExceeded is returned when either cap is
// hit, and no partial output is left behind (the temp dir is removed).
func ExtractTarGz(srcPath, dstDir string) ([]string, error) {
	return extractTarGz(srcPath, dstDir, defaultMaxExtractSize, defaultMaxExtractEntries)
}

// extractTarGz is the bounded implementation of ExtractTarGz. maxBytes caps the
// cumulative uncompressed bytes written; maxEntries caps the number of tar
// entries. It is a separate function (rather than reading package constants
// directly) so tests can exercise the limits with small, fast archives.
func extractTarGz(srcPath, dstDir string, maxBytes int64, maxEntries int) ([]string, error) {
	// Extract to a temporary directory next to dstDir, then rename atomically.
	parentDir := filepath.Dir(dstDir)
	if err := os.MkdirAll(parentDir, 0o755); err != nil {
		return nil, fmt.Errorf("creating parent dir: %w", err)
	}

	tmpDir, err := os.MkdirTemp(parentDir, ".extract-*")
	if err != nil {
		return nil, fmt.Errorf("creating temp dir: %w", err)
	}
	cleanup := true
	defer func() {
		if cleanup {
			_ = os.RemoveAll(tmpDir)
		}
	}()

	f, err := os.Open(srcPath)
	if err != nil {
		return nil, fmt.Errorf("opening archive: %w", err)
	}
	defer func() { _ = f.Close() }()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)
	var extracted []string

	// remaining is the running uncompressed-byte budget shared across all
	// entries; entryCount enforces the per-archive entry cap.
	remaining := maxBytes
	entryCount := 0

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entry: %w", err)
		}

		entryCount++
		if entryCount > maxEntries {
			return nil, fmt.Errorf("%w: archive has more than %d entries", ErrSizeExceeded, maxEntries)
		}

		if err := validateTarEntry(hdr, tmpDir); err != nil {
			return nil, err
		}

		target := filepath.Join(tmpDir, filepath.Clean(hdr.Name))

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, os.FileMode(hdr.Mode)&0o777|0o755); err != nil {
				return nil, fmt.Errorf("creating directory %s: %w", hdr.Name, err)
			}

		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				return nil, fmt.Errorf("creating parent for %s: %w", hdr.Name, err)
			}
			// Bound this entry to the remaining budget. extractFile reads at most
			// remaining+1 bytes so we can distinguish "exactly at the limit"
			// (allowed) from "over the limit" (rejected) exactly.
			n, err := extractFile(target, tr, hdr.FileInfo().Mode(), remaining)
			if err != nil {
				return nil, fmt.Errorf("extracting %s: %w", hdr.Name, err)
			}
			if n > remaining {
				return nil, fmt.Errorf("%w: uncompressed size exceeds %d bytes", ErrSizeExceeded, maxBytes)
			}
			remaining -= n
			extracted = append(extracted, filepath.Clean(hdr.Name))

		case tar.TypeSymlink:
			// Validate symlink target doesn't escape.
			linkTarget := hdr.Linkname
			if !filepath.IsAbs(linkTarget) {
				linkTarget = filepath.Join(filepath.Dir(target), linkTarget)
			}
			linkTarget = filepath.Clean(linkTarget)
			relToTmp, err := filepath.Rel(tmpDir, linkTarget)
			if err != nil || strings.HasPrefix(relToTmp, "..") {
				return nil, fmt.Errorf("%w: symlink %s -> %s escapes destination", ErrPathTraversal, hdr.Name, hdr.Linkname)
			}
			if err := os.Symlink(hdr.Linkname, target); err != nil {
				return nil, fmt.Errorf("creating symlink %s: %w", hdr.Name, err)
			}
			extracted = append(extracted, filepath.Clean(hdr.Name))
		}
	}

	// Atomic rename: remove destination if it exists, then rename temp.
	_ = os.RemoveAll(dstDir)
	if err := os.Rename(tmpDir, dstDir); err != nil {
		return nil, fmt.Errorf("renaming extracted dir: %w", err)
	}
	cleanup = false

	return extracted, nil
}

// SetExecutable adds executable permission bits to a file.
func SetExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return fmt.Errorf("stat %s: %w", path, err)
	}
	return os.Chmod(path, info.Mode()|0o111)
}

// validateTarEntry checks that a tar header does not contain path traversal.
func validateTarEntry(hdr *tar.Header, dstDir string) error {
	clean := filepath.Clean(hdr.Name)

	// Reject absolute paths (check both OS-native and Unix-style for cross-platform safety).
	if filepath.IsAbs(clean) || strings.HasPrefix(hdr.Name, "/") {
		return fmt.Errorf("%w: absolute path %q", ErrPathTraversal, hdr.Name)
	}

	// Reject entries that start with ".." or contain "..".
	if clean == ".." || strings.HasPrefix(clean, ".."+string(filepath.Separator)) {
		return fmt.Errorf("%w: %q escapes destination", ErrPathTraversal, hdr.Name)
	}

	// Double-check the resolved path is within dstDir.
	resolved := filepath.Join(dstDir, clean)
	rel, err := filepath.Rel(dstDir, resolved)
	if err != nil || strings.HasPrefix(rel, "..") {
		return fmt.Errorf("%w: %q resolves outside destination", ErrPathTraversal, hdr.Name)
	}

	return nil
}

// extractFile writes a tar entry to disk atomically, reading at most limit+1
// bytes from r. It returns the number of bytes written. Reading one byte past
// the limit lets the caller detect an over-budget entry exactly (n > limit)
// while an entry sized exactly at the limit still succeeds. Because at most
// limit+1 bytes are ever written before the caller aborts and removes the temp
// dir, a decompression bomb cannot write unbounded output to disk.
func extractFile(target string, r io.Reader, mode os.FileMode, limit int64) (int64, error) {
	tmp := target + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode&0o777|0o644)
	if err != nil {
		return 0, err
	}

	n, err := io.Copy(f, io.LimitReader(r, limit+1))
	if err != nil {
		_ = f.Close()
		_ = os.Remove(tmp)
		return n, err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return n, err
	}

	return n, os.Rename(tmp, target)
}
