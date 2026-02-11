package oci

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// createTestTarGz creates a tar.gz archive at dstPath with the given file entries.
func createTestTarGz(t *testing.T, dstPath string, entries map[string]string) {
	t.Helper()

	f, err := os.Create(dstPath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o644,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("writing tar header for %s: %v", name, err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("writing tar content for %s: %v", name, err)
		}
	}
}

// createTestTarGzWithHeader creates a tar.gz with custom headers.
func createTestTarGzWithHeader(t *testing.T, dstPath string, headers []*tar.Header) {
	t.Helper()

	f, err := os.Create(dstPath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}
	defer f.Close()

	gw := gzip.NewWriter(f)
	defer gw.Close()

	tw := tar.NewWriter(gw)
	defer tw.Close()

	for _, hdr := range headers {
		if err := tw.WriteHeader(hdr); err != nil {
			t.Fatalf("writing tar header: %v", err)
		}
		if hdr.Typeflag == tar.TypeReg && hdr.Size > 0 {
			data := make([]byte, hdr.Size)
			if _, err := tw.Write(data); err != nil {
				t.Fatalf("writing tar content: %v", err)
			}
		}
	}
}

func TestExtractTarGz(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	entries := map[string]string{
		"bin/plugin":    "#!/bin/sh\necho hello",
		"lib/helper.so": "fake library content",
		"README.md":     "# Plugin\nDocumentation",
	}
	createTestTarGz(t, archivePath, entries)

	extracted, err := ExtractTarGz(archivePath, extractDir)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	if len(extracted) != 3 {
		t.Fatalf("extracted %d files, want 3", len(extracted))
	}

	// Verify file contents.
	for name, wantContent := range entries {
		got, err := os.ReadFile(filepath.Join(extractDir, name))
		if err != nil {
			t.Errorf("reading %s: %v", name, err)
			continue
		}
		if string(got) != wantContent {
			t.Errorf("%s content = %q, want %q", name, got, wantContent)
		}
	}
}

func TestExtractTarGzPathTraversal(t *testing.T) {
	tmpDir := t.TempDir()

	tests := []struct {
		name    string
		headers []*tar.Header
	}{
		{
			name: "dotdot prefix",
			headers: []*tar.Header{
				{Name: "../escape.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg},
			},
		},
		{
			name: "nested dotdot",
			headers: []*tar.Header{
				{Name: "subdir/../../escape.txt", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg},
			},
		},
		{
			name: "absolute path",
			headers: []*tar.Header{
				{Name: "/etc/passwd", Mode: 0o644, Size: 5, Typeflag: tar.TypeReg},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			archivePath := filepath.Join(tmpDir, tt.name+".tar.gz")
			extractDir := filepath.Join(tmpDir, tt.name+"-extracted")
			createTestTarGzWithHeader(t, archivePath, tt.headers)

			_, err := ExtractTarGz(archivePath, extractDir)
			if !errors.Is(err, ErrPathTraversal) {
				t.Errorf("error = %v, want %v", err, ErrPathTraversal)
			}
		})
	}
}

func TestExtractTarGzSymlinkEscape(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "symlink-escape.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	headers := []*tar.Header{
		{Name: "escape", Typeflag: tar.TypeSymlink, Linkname: "../../etc/passwd"},
	}
	createTestTarGzWithHeader(t, archivePath, headers)

	_, err := ExtractTarGz(archivePath, extractDir)
	if !errors.Is(err, ErrPathTraversal) {
		t.Errorf("error = %v, want %v", err, ErrPathTraversal)
	}
}

func TestDetectFormat(t *testing.T) {
	tmpDir := t.TempDir()

	// Create a gzip file.
	gzPath := filepath.Join(tmpDir, "test.tar.gz")
	createTestTarGz(t, gzPath, map[string]string{"file.txt": "content"})

	format, err := DetectFormat(gzPath)
	if err != nil {
		t.Fatalf("DetectFormat tar.gz: %v", err)
	}
	if format != FormatTarGz {
		t.Errorf("format = %d, want FormatTarGz (%d)", format, FormatTarGz)
	}

	// Create a raw binary.
	binPath := filepath.Join(tmpDir, "binary")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\necho hello"), 0o755); err != nil {
		t.Fatalf("writing binary: %v", err)
	}

	format, err = DetectFormat(binPath)
	if err != nil {
		t.Fatalf("DetectFormat binary: %v", err)
	}
	if format != FormatRawBinary {
		t.Errorf("format = %d, want FormatRawBinary (%d)", format, FormatRawBinary)
	}
}

func TestDetectFormatNonexistent(t *testing.T) {
	_, err := DetectFormat("/nonexistent/file")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestSetExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "binary")

	if err := os.WriteFile(path, []byte("binary"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if err := SetExecutable(path); err != nil {
		t.Fatalf("SetExecutable: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	if info.Mode()&0o111 == 0 {
		t.Errorf("file mode %v does not have executable bits", info.Mode())
	}
}

func TestExtractTarGzAtomicity(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "test.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	// First extraction.
	createTestTarGz(t, archivePath, map[string]string{"v1.txt": "version 1"})
	if _, err := ExtractTarGz(archivePath, extractDir); err != nil {
		t.Fatalf("first extraction: %v", err)
	}

	// Second extraction should replace atomically.
	createTestTarGz(t, archivePath, map[string]string{"v2.txt": "version 2"})
	if _, err := ExtractTarGz(archivePath, extractDir); err != nil {
		t.Fatalf("second extraction: %v", err)
	}

	// v1.txt should not exist, v2.txt should.
	if _, err := os.Stat(filepath.Join(extractDir, "v1.txt")); !os.IsNotExist(err) {
		t.Error("v1.txt should have been removed by atomic replacement")
	}

	got, err := os.ReadFile(filepath.Join(extractDir, "v2.txt"))
	if err != nil {
		t.Fatalf("reading v2.txt: %v", err)
	}
	if string(got) != "version 2" {
		t.Errorf("v2.txt = %q, want %q", got, "version 2")
	}
}

// TestSetExecutableNonexistent tests SetExecutable with a path that does not exist.
func TestSetExecutableNonexistent(t *testing.T) {
	err := SetExecutable("/nonexistent/path/binary")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

// TestSetExecutableAlreadyExecutable verifies SetExecutable is idempotent.
func TestSetExecutableAlreadyExecutable(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "already-exec")

	if err := os.WriteFile(path, []byte("binary"), 0o755); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	if err := SetExecutable(path); err != nil {
		t.Fatalf("SetExecutable: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("file should still be executable")
	}
}

// TestExtractTarGzWithSymlinkInside tests that valid symlinks within the
// extraction directory are created correctly.
func TestExtractTarGzWithSymlinkInside(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "symlink-ok.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Write a regular file first.
	content := "target file content"
	if err := tw.WriteHeader(&tar.Header{
		Name:     "target.txt",
		Mode:     0o644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("writing content: %v", err)
	}

	// Write a symlink pointing to the regular file (within the directory).
	if err := tw.WriteHeader(&tar.Header{
		Name:     "link.txt",
		Typeflag: tar.TypeSymlink,
		Linkname: "target.txt",
	}); err != nil {
		t.Fatalf("writing symlink header: %v", err)
	}

	tw.Close()
	gw.Close()
	f.Close()

	extracted, err := ExtractTarGz(archivePath, extractDir)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	if len(extracted) != 2 {
		t.Fatalf("extracted %d files, want 2", len(extracted))
	}

	// Verify the symlink resolves correctly.
	linkTarget, err := os.Readlink(filepath.Join(extractDir, "link.txt"))
	if err != nil {
		t.Fatalf("readlink: %v", err)
	}
	if linkTarget != "target.txt" {
		t.Errorf("symlink target = %q, want %q", linkTarget, "target.txt")
	}
}

// TestExtractTarGzWithDirectoryEntry tests extraction of directories in the archive.
func TestExtractTarGzWithDirectoryEntry(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "dirs.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	// Add a directory entry.
	if err := tw.WriteHeader(&tar.Header{
		Name:     "subdir/",
		Mode:     0o755,
		Typeflag: tar.TypeDir,
	}); err != nil {
		t.Fatalf("writing dir header: %v", err)
	}

	// Add a file inside the directory.
	content := "nested file"
	if err := tw.WriteHeader(&tar.Header{
		Name:     "subdir/file.txt",
		Mode:     0o644,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("writing file header: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("writing file content: %v", err)
	}

	tw.Close()
	gw.Close()
	f.Close()

	extracted, err := ExtractTarGz(archivePath, extractDir)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	// Only regular files and symlinks are listed in extracted (not directories).
	if len(extracted) != 1 {
		t.Fatalf("extracted %d files, want 1", len(extracted))
	}

	// Verify the directory was created.
	info, err := os.Stat(filepath.Join(extractDir, "subdir"))
	if err != nil {
		t.Fatalf("stat subdir: %v", err)
	}
	if !info.IsDir() {
		t.Error("subdir should be a directory")
	}

	// Verify the nested file.
	got, err := os.ReadFile(filepath.Join(extractDir, "subdir", "file.txt"))
	if err != nil {
		t.Fatalf("reading file: %v", err)
	}
	if string(got) != content {
		t.Errorf("content = %q, want %q", got, content)
	}
}

// TestExtractTarGzInvalidArchive tests ExtractTarGz with a file that is not a
// valid gzip file.
func TestExtractTarGzInvalidArchive(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "invalid.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	// Write a non-gzip file.
	if err := os.WriteFile(archivePath, []byte("this is not gzip"), 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := ExtractTarGz(archivePath, extractDir)
	if err == nil {
		t.Error("expected error for invalid gzip file")
	}
}

// TestExtractTarGzNonexistentSource tests ExtractTarGz with a nonexistent
// source file.
func TestExtractTarGzNonexistentSource(t *testing.T) {
	tmpDir := t.TempDir()
	_, err := ExtractTarGz(filepath.Join(tmpDir, "missing.tar.gz"), filepath.Join(tmpDir, "out"))
	if err == nil {
		t.Error("expected error for nonexistent source")
	}
}

// TestExtractTarGzFilePermissions tests that extracted files have the correct
// permission bits set.
func TestExtractTarGzFilePermissions(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "perms.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	content := "#!/bin/sh\necho executable"
	if err := tw.WriteHeader(&tar.Header{
		Name:     "script.sh",
		Mode:     0o755,
		Size:     int64(len(content)),
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("writing header: %v", err)
	}
	if _, err := tw.Write([]byte(content)); err != nil {
		t.Fatalf("writing content: %v", err)
	}

	tw.Close()
	gw.Close()
	f.Close()

	_, err = ExtractTarGz(archivePath, extractDir)
	if err != nil {
		t.Fatalf("ExtractTarGz: %v", err)
	}

	info, err := os.Stat(filepath.Join(extractDir, "script.sh"))
	if err != nil {
		t.Fatalf("stat: %v", err)
	}

	// The extractFile function applies mode&0o777|0o644, so 0o755 should be preserved.
	if info.Mode()&0o111 == 0 {
		t.Error("script.sh should have executable bits set")
	}
}

// TestDetectFormatEmptyFile tests DetectFormat with an empty file.
func TestDetectFormatEmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "empty")
	if err := os.WriteFile(path, []byte{}, 0o644); err != nil {
		t.Fatalf("writing file: %v", err)
	}

	_, err := DetectFormat(path)
	if err == nil {
		t.Error("expected error for empty file")
	}
}
