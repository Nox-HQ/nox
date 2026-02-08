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

// gzipMagic is the two-byte magic number for gzip files.
var gzipMagic = []byte{0x1f, 0x8b}

// DetectFormat inspects the first bytes of a file to determine its format.
func DetectFormat(path string) (ArtifactFormat, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, fmt.Errorf("opening file for format detection: %w", err)
	}
	defer f.Close()

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
func ExtractTarGz(srcPath, dstDir string) ([]string, error) {
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
	defer f.Close()

	gz, err := gzip.NewReader(f)
	if err != nil {
		return nil, fmt.Errorf("creating gzip reader: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(gz)
	var extracted []string

	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("reading tar entry: %w", err)
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
			if err := extractFile(target, tr, hdr.FileInfo().Mode()); err != nil {
				return nil, fmt.Errorf("extracting %s: %w", hdr.Name, err)
			}
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

	// Reject absolute paths.
	if filepath.IsAbs(clean) {
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

// extractFile writes a tar entry to disk atomically.
func extractFile(target string, r io.Reader, mode os.FileMode) error {
	tmp := target + ".tmp"
	f, err := os.OpenFile(tmp, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode&0o777|0o644)
	if err != nil {
		return err
	}

	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		_ = os.Remove(tmp)
		return err
	}
	if err := f.Close(); err != nil {
		_ = os.Remove(tmp)
		return err
	}

	return os.Rename(tmp, target)
}
