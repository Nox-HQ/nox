package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"debug/buildinfo"
	"encoding/hex"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// `nox sbom` on a release archive holding a Go executable: the document is
// about the archive (named, with its digest), contains the binary's modules
// and the standard library at the Go release it was built with, and comes out
// the same on every run. Flags after the artifact are accepted, as GoReleaser
// passes them.
func TestSBOMCommandDescribesAReleaseArchive(t *testing.T) {
	// A real Go executable with a known dependency, built here so its build
	// info does not depend on how this test binary was built.
	dir := t.TempDir()
	self := filepath.Join(dir, "gobin")
	if out, err := exec.Command("go", "build", "-o", self,
		"github.com/nox-hq/nox/core/analyzers/deps/testdata/gobin").CombinedOutput(); err != nil {
		t.Fatalf("building the Go fixture: %v\n%s", err, out)
	}
	bin, err := os.ReadFile(self)
	if err != nil {
		t.Fatal(err)
	}
	bi, err := buildinfo.ReadFile(self)
	if err != nil || len(bi.Deps) == 0 {
		t.Fatalf("the fixture carries no module build info: %v", err)
	}

	archive := filepath.Join(dir, "nox_9.9.9_linux_amd64.tar.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	_ = tw.WriteHeader(&tar.Header{Name: "nox", Mode: 0o755, Size: int64(len(bin)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(bin)
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())

	t.Setenv("SOURCE_DATE_EPOCH", "1762250000")
	gen := func(out string) []byte {
		var stdout, stderr bytes.Buffer
		if code := sbomCmd([]string{archive, "-output", out}, &stdout, &stderr); code != 0 {
			t.Fatalf("exit %d: %s", code, stderr.String())
		}
		data, err := os.ReadFile(out)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	first := gen(filepath.Join(dir, "a.json"))
	if second := gen(filepath.Join(dir, "b.json")); !bytes.Equal(first, second) {
		t.Error("two runs on the same archive wrote different documents")
	}

	var doc struct {
		Name     string `json:"name"`
		Packages []struct {
			SPDXID    string `json:"SPDXID"`
			Name      string `json:"name"`
			Version   string `json:"versionInfo"`
			Checksums []struct {
				Value string `json:"checksumValue"`
			} `json:"checksums"`
		} `json:"packages"`
	}
	if err := json.Unmarshal(first, &doc); err != nil {
		t.Fatal(err)
	}
	if doc.Name != filepath.Base(archive) {
		t.Errorf("document name %q", doc.Name)
	}
	got := map[string]string{}
	for _, p := range doc.Packages {
		got[p.Name] = p.Version
		if p.SPDXID == "SPDXRef-Subject" && (len(p.Checksums) != 1 || p.Checksums[0].Value != hex.EncodeToString(sum[:])) {
			t.Errorf("subject checksums %+v, want the archive's sha256", p.Checksums)
		}
	}
	if want := strings.TrimPrefix(strings.Fields(runtime.Version())[0], "go"); got["stdlib"] != want {
		t.Errorf("stdlib %q, want %q", got["stdlib"], want)
	}
	for _, d := range bi.Deps {
		if d.Replace == nil && got[d.Path] != d.Version {
			t.Errorf("module %s: %q, want %q", d.Path, got[d.Path], d.Version)
		}
	}
}

// -format cyclonedx writes the same artifact's BOM as CycloneDX, with the
// archive as its subject; the default stays SPDX, which the release uses.
func TestSBOMCommandWritesCycloneDX(t *testing.T) {
	dir := t.TempDir()
	archive := filepath.Join(dir, "app_1.0.0_linux_amd64.tar.gz")
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	lock := []byte(`{"lockfileVersion":3,"packages":{"":{"dependencies":{"lodash":"4.17.21"}},"node_modules/lodash":{"version":"4.17.21"}}}`)
	_ = tw.WriteHeader(&tar.Header{Name: "package-lock.json", Mode: 0o644, Size: int64(len(lock)), Typeflag: tar.TypeReg})
	_, _ = tw.Write(lock)
	_ = tw.Close()
	_ = gz.Close()
	if err := os.WriteFile(archive, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(buf.Bytes())

	var out, errw bytes.Buffer
	if code := sbomCmd([]string{archive, "-format", "cyclonedx"}, &out, &errw); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	var doc struct {
		BOMFormat string `json:"bomFormat"`
		Metadata  struct {
			Component struct {
				Name   string `json:"name"`
				Hashes []struct {
					Content string `json:"content"`
				} `json:"hashes"`
			} `json:"component"`
		} `json:"metadata"`
		Components []struct {
			Name, Version string
		} `json:"components"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("not JSON: %v\n%s", err, out.String())
	}
	if doc.BOMFormat != "CycloneDX" || doc.Metadata.Component.Name != filepath.Base(archive) {
		t.Errorf("format %q subject %q", doc.BOMFormat, doc.Metadata.Component.Name)
	}
	if h := doc.Metadata.Component.Hashes; len(h) != 1 || h[0].Content != hex.EncodeToString(sum[:]) {
		t.Errorf("subject hashes %+v", h)
	}
	if len(doc.Components) != 1 || doc.Components[0].Name != "lodash" {
		t.Errorf("components %+v", doc.Components)
	}

	out.Reset()
	if code := sbomCmd([]string{archive, "-format", "pdf"}, &out, &errw); code != 2 {
		t.Errorf("an unknown format: exit %d, want 2", code)
	}
}
