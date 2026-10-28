package git

import (
	"archive/tar"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExportTree_WritesTheRefNotTheWorkingTree(t *testing.T) {
	dir := setupGitRepo(t)
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("committed\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	run(t, dir, "git", "add", ".")
	run(t, dir, "git", "commit", "-m", "add")
	// Dirty the working tree after the commit.
	if err := os.WriteFile(filepath.Join(dir, "sub", "a.txt"), []byte("dirty\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "untracked.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}

	dest := t.TempDir()
	if err := ExportTree(dir, "HEAD", dest); err != nil {
		t.Fatalf("ExportTree: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dest, "sub", "a.txt"))
	if err != nil || string(got) != "committed\n" {
		t.Fatalf("exported %q, %v; want the committed content", got, err)
	}
	if _, err := os.Stat(filepath.Join(dest, "untracked.txt")); !os.IsNotExist(err) {
		t.Errorf("an untracked file was exported")
	}
}

func TestExportTree_UnknownRefIsAnError(t *testing.T) {
	dir := setupGitRepo(t)
	if err := ExportTree(dir, "no-such-ref", t.TempDir()); err == nil {
		t.Fatal("an unknown ref must be an error, not an empty tree")
	}
}

func TestExtractTar_RejectsEntriesThatEscape(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	body := []byte("pwn")
	if err := tw.WriteHeader(&tar.Header{Name: "../escape.txt", Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write(body); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	err := extractTar(&buf, dest)
	if err == nil || !strings.Contains(err.Error(), "escapes") {
		t.Fatalf("err = %v, want a refusal", err)
	}
	if _, serr := os.Stat(filepath.Join(filepath.Dir(dest), "escape.txt")); serr == nil {
		t.Error("the entry was written outside the destination")
	}
}

func TestExtractTar_SkipsSymlinks(t *testing.T) {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if err := tw.WriteHeader(&tar.Header{Name: "link", Linkname: "/etc/passwd", Typeflag: tar.TypeSymlink}); err != nil {
		t.Fatal(err)
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := extractTar(&buf, dest); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dest, "link")); !os.IsNotExist(err) {
		t.Error("a symlink was recreated")
	}
}
