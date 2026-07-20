package oci

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// createTestTarGz creates a tar.gz archive at dstPath with the given file entries.
func createTestTarGz(t *testing.T, dstPath string, entries map[string]string) {
	t.Helper()

	f, err := os.Create(dstPath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

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
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	defer func() { _ = gw.Close() }()

	tw := tar.NewWriter(gw)
	defer func() { _ = tw.Close() }()

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
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions are not supported on Windows")
	}
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
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions are not supported on Windows")
	}
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

	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

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

	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

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
	if runtime.GOOS == "windows" {
		t.Skip("Unix file permissions are not supported on Windows")
	}
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

	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

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

// createTestTarGzZeros writes a tar.gz containing a single regular-file entry
// of `size` zero bytes. Zeros are highly compressible, so the resulting archive
// is tiny while the uncompressed payload is `size` — the shape of a
// decompression bomb.
func createTestTarGzZeros(t *testing.T, dstPath, name string, size int64) {
	t.Helper()

	f, err := os.Create(dstPath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}
	defer func() { _ = f.Close() }()

	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)

	if err := tw.WriteHeader(&tar.Header{
		Name:     name,
		Mode:     0o644,
		Size:     size,
		Typeflag: tar.TypeReg,
	}); err != nil {
		t.Fatalf("writing tar header: %v", err)
	}
	if _, err := io.CopyN(tw, zeroReader{}, size); err != nil {
		t.Fatalf("writing tar content: %v", err)
	}

	if err := tw.Close(); err != nil {
		t.Fatalf("closing tar writer: %v", err)
	}
	if err := gw.Close(); err != nil {
		t.Fatalf("closing gzip writer: %v", err)
	}
}

// zeroReader is an infinite source of zero bytes.
type zeroReader struct{}

func (zeroReader) Read(p []byte) (int, error) {
	for i := range p {
		p[i] = 0
	}
	return len(p), nil
}

// TestExtractTarGzDecompressionBomb verifies that an archive whose uncompressed
// payload far exceeds the budget is rejected with ErrSizeExceeded, and that the
// full expanded output is not written to disk.
func TestExtractTarGzDecompressionBomb(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "bomb.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	// 8 MiB of zeros, but a 64 KiB budget: ~128x over the cap.
	const payload = 8 * 1024 * 1024
	const maxBytes = 64 * 1024
	createTestTarGzZeros(t, archivePath, "bomb.bin", payload)

	// The compressed archive is tiny (zeros compress ~1000x); confirm it would
	// pass the 500 MB download cap yet expand far beyond the extract budget.
	info, err := os.Stat(archivePath)
	if err != nil {
		t.Fatalf("stat archive: %v", err)
	}
	if info.Size() >= maxBytes {
		t.Fatalf("test archive %d bytes is not smaller than the budget; not a bomb", info.Size())
	}

	_, err = extractTarGz(archivePath, extractDir, maxBytes, defaultMaxExtractEntries)
	if !errors.Is(err, ErrSizeExceeded) {
		t.Fatalf("error = %v, want ErrSizeExceeded", err)
	}

	// The atomic rename never happens on failure, so the destination must not
	// exist. This is what fails on the unbounded (buggy) code, which writes all
	// 8 MiB and renames it into place.
	if _, statErr := os.Stat(extractDir); !os.IsNotExist(statErr) {
		t.Errorf("extract dir exists after bomb rejection: %v", statErr)
	}

	// Nothing near the full payload should remain anywhere under tmpDir (the
	// archive itself is tiny). Bound it well under the payload to prove the
	// bomb was not written unbounded.
	total, err := dirSize(tmpDir)
	if err != nil {
		t.Fatalf("measuring tmpDir: %v", err)
	}
	if leftover := total - info.Size(); leftover > 2*maxBytes {
		t.Errorf("leftover extracted bytes = %d, want <= %d (bomb written unbounded)", leftover, 2*maxBytes)
	}
}

// TestExtractTarGzSizeBoundaryExact verifies the LimitReader boundary is exact:
// an entry sized exactly at the budget succeeds, one byte over fails.
func TestExtractTarGzSizeBoundaryExact(t *testing.T) {
	const maxBytes = 4096

	t.Run("exactly at limit succeeds", func(t *testing.T) {
		tmpDir := t.TempDir()
		archivePath := filepath.Join(tmpDir, "exact.tar.gz")
		extractDir := filepath.Join(tmpDir, "extracted")
		createTestTarGzZeros(t, archivePath, "exact.bin", maxBytes)

		extracted, err := extractTarGz(archivePath, extractDir, maxBytes, defaultMaxExtractEntries)
		if err != nil {
			t.Fatalf("extractTarGz at exact limit: %v", err)
		}
		if len(extracted) != 1 {
			t.Fatalf("extracted %d files, want 1", len(extracted))
		}
		info, err := os.Stat(filepath.Join(extractDir, "exact.bin"))
		if err != nil {
			t.Fatalf("stat extracted file: %v", err)
		}
		if info.Size() != maxBytes {
			t.Errorf("extracted size = %d, want %d", info.Size(), maxBytes)
		}
	})

	t.Run("one byte over limit fails", func(t *testing.T) {
		tmpDir := t.TempDir()
		archivePath := filepath.Join(tmpDir, "over.tar.gz")
		extractDir := filepath.Join(tmpDir, "extracted")
		createTestTarGzZeros(t, archivePath, "over.bin", maxBytes+1)

		_, err := extractTarGz(archivePath, extractDir, maxBytes, defaultMaxExtractEntries)
		if !errors.Is(err, ErrSizeExceeded) {
			t.Fatalf("error = %v, want ErrSizeExceeded", err)
		}
	})
}

// TestExtractTarGzBudgetSpansEntries verifies the budget is cumulative across
// entries: several entries that individually fit but together exceed the budget
// are rejected.
func TestExtractTarGzBudgetSpansEntries(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "multi.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	f, err := os.Create(archivePath)
	if err != nil {
		t.Fatalf("creating tar.gz: %v", err)
	}
	gw := gzip.NewWriter(f)
	tw := tar.NewWriter(gw)
	// Three 1 KiB entries = 3 KiB total against a 2 KiB budget.
	for i := 0; i < 3; i++ {
		if err := tw.WriteHeader(&tar.Header{
			Name:     "part" + string(rune('a'+i)) + ".bin",
			Mode:     0o644,
			Size:     1024,
			Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatalf("writing header: %v", err)
		}
		if _, err := io.CopyN(tw, zeroReader{}, 1024); err != nil {
			t.Fatalf("writing content: %v", err)
		}
	}
	_ = tw.Close()
	_ = gw.Close()
	_ = f.Close()

	_, err = extractTarGz(archivePath, extractDir, 2048, defaultMaxExtractEntries)
	if !errors.Is(err, ErrSizeExceeded) {
		t.Fatalf("error = %v, want ErrSizeExceeded (cumulative budget)", err)
	}
	if _, statErr := os.Stat(extractDir); !os.IsNotExist(statErr) {
		t.Errorf("extract dir should not exist after budget exceeded")
	}
}

// TestExtractTarGzEntryCountCap verifies the entry-count cap rejects a
// "many tiny files" bomb.
func TestExtractTarGzEntryCountCap(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "manyfiles.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	entries := make(map[string]string, 20)
	for i := 0; i < 20; i++ {
		entries["f"+string(rune('a'+i))] = "x"
	}
	createTestTarGz(t, archivePath, entries)

	_, err := extractTarGz(archivePath, extractDir, defaultMaxExtractSize, 5)
	if !errors.Is(err, ErrSizeExceeded) {
		t.Fatalf("error = %v, want ErrSizeExceeded (entry cap)", err)
	}
}

// TestExtractTarGzLegitimateUnderCap verifies a normal, small plugin archive
// still extracts correctly under the default caps via the public entrypoint.
func TestExtractTarGzLegitimateUnderCap(t *testing.T) {
	tmpDir := t.TempDir()
	archivePath := filepath.Join(tmpDir, "plugin.tar.gz")
	extractDir := filepath.Join(tmpDir, "extracted")

	entries := map[string]string{
		"bin/nox-plugin": "#!/bin/sh\necho real plugin",
		"lib/support.so": "some binary-ish payload",
		"LICENSE":        "MIT",
	}
	createTestTarGz(t, archivePath, entries)

	extracted, err := ExtractTarGz(archivePath, extractDir)
	if err != nil {
		t.Fatalf("ExtractTarGz on legitimate archive: %v", err)
	}
	if len(extracted) != len(entries) {
		t.Fatalf("extracted %d files, want %d", len(extracted), len(entries))
	}
	for name, want := range entries {
		got, err := os.ReadFile(filepath.Join(extractDir, name))
		if err != nil {
			t.Errorf("reading %s: %v", name, err)
			continue
		}
		if string(got) != want {
			t.Errorf("%s content = %q, want %q", name, got, want)
		}
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
