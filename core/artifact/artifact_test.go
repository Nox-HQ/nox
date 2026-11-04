package artifact

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type entry struct {
	name    string
	body    string
	symlink string
}

func writeTarGz(t *testing.T, path string, entries []entry) {
	t.Helper()
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, e := range entries {
		h := &tar.Header{Name: e.name, Mode: 0o644, Size: int64(len(e.body)), Typeflag: tar.TypeReg}
		if e.symlink != "" {
			h = &tar.Header{Name: e.name, Linkname: e.symlink, Typeflag: tar.TypeSymlink}
		}
		if err := tw.WriteHeader(h); err != nil {
			t.Fatal(err)
		}
		if e.symlink == "" {
			_, _ = tw.Write([]byte(e.body))
		}
	}
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func writeZip(t *testing.T, path string, entries []entry) {
	t.Helper()
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, e := range entries {
		w, err := zw.Create(e.name)
		if err != nil {
			t.Fatal(err)
		}
		_, _ = w.Write([]byte(e.body))
	}
	_ = zw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

func digest(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// Each supported form lands as a directory holding the artifact's files, and
// the result names the artifact and its SHA-256.
func TestOpenExtractsEachForm(t *testing.T) {
	dir := t.TempDir()
	files := []entry{{name: "nox", body: "binary"}, {name: "docs/README.md", body: "readme"}}
	cases := map[string]func(string){
		"nox_1.0.0_linux_amd64.tar.gz": func(p string) { writeTarGz(t, p, files) },
		"nox_1.0.0_windows_amd64.zip":  func(p string) { writeZip(t, p, files) },
	}
	for name, write := range cases {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(dir, name)
			write(p)
			a, err := Open(p, t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			if a.Name != name || a.SHA256 != digest(t, p) {
				t.Errorf("artifact %q %s, want %q %s", a.Name, a.SHA256, name, digest(t, p))
			}
			for _, f := range files {
				if b, err := os.ReadFile(filepath.Join(a.Dir, f.name)); err != nil || string(b) != f.body {
					t.Errorf("%s: %q, %v", f.name, b, err)
				}
			}
		})
	}

	t.Run("a single file", func(t *testing.T) {
		p := filepath.Join(dir, "nox")
		if err := os.WriteFile(p, []byte("binary"), 0o755); err != nil {
			t.Fatal(err)
		}
		a, err := Open(p, t.TempDir())
		if err != nil {
			t.Fatal(err)
		}
		if b, _ := os.ReadFile(filepath.Join(a.Dir, "nox")); string(b) != "binary" || a.SHA256 != digest(t, p) {
			t.Errorf("single file: %q in %s, sha %s", b, a.Dir, a.SHA256)
		}
	})
}

// An entry that would land outside the extraction directory, an absolute
// path, or a link fails the whole artifact: an SBOM of a partly read archive
// would understate it.
func TestOpenRefusesEntriesThatEscapeOrLink(t *testing.T) {
	for name, entries := range map[string][]entry{
		"parent":   {{name: "../evil", body: "x"}},
		"nested":   {{name: "a/../../evil", body: "x"}},
		"absolute": {{name: "/etc/evil", body: "x"}},
		"symlink":  {{name: "link", symlink: "/etc/passwd"}},
	} {
		t.Run(name, func(t *testing.T) {
			p := filepath.Join(t.TempDir(), "a.tar.gz")
			writeTarGz(t, p, entries)
			out := t.TempDir()
			if _, err := Open(p, out); err == nil {
				t.Fatal("accepted")
			}
			if _, err := os.Stat(filepath.Join(filepath.Dir(out), "evil")); err == nil {
				t.Fatal("a file was written outside the extraction directory")
			}
		})
	}
}

// An archive that expands beyond the budget is refused rather than truncated.
func TestOpenRefusesAnArchiveOverBudget(t *testing.T) {
	p := filepath.Join(t.TempDir(), "big.tar.gz")
	writeTarGz(t, p, []entry{{name: "big", body: strings.Repeat("0", 4096)}})
	if _, err := open(p, t.TempDir(), limits{maxBytes: 1024, maxFiles: 10}); err == nil ||
		!strings.Contains(err.Error(), "budget") {
		t.Fatalf("over-budget archive: %v", err)
	}
}
