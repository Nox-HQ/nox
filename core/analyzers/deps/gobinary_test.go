package deps

import (
	"context"
	"debug/buildinfo"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// copyTestBinary copies the built fixture (testdata/gobin), a real Go
// executable with embedded build info, into dir under name.
func copyTestBinary(t *testing.T, dir, name string) (art discovery.Artifact, bi *buildinfo.BuildInfo) {
	t.Helper()
	src := buildGoFixture(t)
	data, err := os.ReadFile(src)
	if err != nil {
		t.Fatal(err)
	}
	if bi, err = buildinfo.ReadFile(src); err != nil {
		t.Fatalf("the fixture carries no build info: %v", err)
	}
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, data, 0o755); err != nil {
		t.Fatal(err)
	}
	return discovery.Artifact{Path: name, AbsPath: p, Type: discovery.Unknown, Size: int64(len(data))}, bi
}

// A Go executable in the tree is inventoried from the build information the
// toolchain embedded in it: its modules at the versions it was built with, and
// the standard library at the exact Go release, which no go.mod states. The
// packages are located at the binary and marked as coming from one.
func TestGoBinaryIsInventoriedFromItsBuildInfo(t *testing.T) {
	art, bi := copyTestBinary(t, t.TempDir(), "some-tool")
	inv, _, err := NewAnalyzer(WithOSVDisabled()).ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]Package{}
	for _, p := range inv.Packages() {
		got[p.Name] = p
	}

	std, ok := got["stdlib"]
	want := strings.TrimPrefix(strings.Fields(runtime.Version())[0], "go")
	if !ok || std.Version != want || std.Ecosystem != "go" || std.Origin != OriginGoBinary {
		t.Errorf("stdlib: %+v, want version %s from a Go binary", std, want)
	}
	if len(bi.Deps) == 0 {
		t.Fatal("the fixture links no modules; it proves nothing")
	}
	if p, ok := got["golang.org/x/sync"]; !ok || p.Version == "" {
		t.Errorf("golang.org/x/sync, which the fixture imports: %+v", p)
	}
	for _, d := range bi.Deps {
		name, version := d.Path, d.Version
		if d.Replace != nil {
			if d.Replace.Version == "" {
				continue
			}
			name, version = d.Replace.Path, d.Replace.Version
		}
		if p, ok := got[name]; !ok || p.Version != version || p.Origin != OriginGoBinary {
			t.Errorf("module %s@%s: got %+v", name, version, p)
		}
	}
}

// End to end, next to a Go module whose build provably does not link the
// affected package: the advisory against the binary's stdlib is located at the
// binary, marked as coming from one, and left undetermined at its full
// severity. Judged by the source tree's link set instead, it would be refuted
// and dropped to info, for code the binary shipped.
func TestGoBinaryFindingIsNotRefutedByTheSourceTree(t *testing.T) {
	dir := t.TempDir()
	mod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(mod, []byte("module example.com/tree\n\ngo 1.21\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\n\nfunc main() {}\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	bin, _ := copyTestBinary(t, dir, "tool")

	std := strings.TrimPrefix(strings.Fields(runtime.Version())[0], "go")
	rec := vulnsource.Record{
		ID:       "GO-2099-0001",
		Summary:  "request smuggling",
		Severity: []vulnsource.Severity{{Type: "CVSS_V3", Score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
		Affected: []vulnsource.Affected{{
			Package:           vulnsource.Package{Name: "stdlib", Ecosystem: "Go"},
			EcosystemSpecific: vulnsource.EcosystemSpecific{Imports: []vulnsource.Import{{Path: "net/http"}}},
		}},
	}
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{"stdlib": {rec}}}
	arts := []discovery.Artifact{{Path: "go.mod", AbsPath: mod, Type: discovery.Lockfile}, bin}
	_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	var got *findings.Finding
	for _, f := range fs.Findings() {
		if f.RuleID == "VULN-001" && f.Metadata["package"] == "stdlib" {
			got = &f
		}
	}
	if got == nil {
		t.Fatalf("no finding for stdlib %s from the binary", std)
	}
	if got.Location.FilePath != "tool" || got.Metadata["package_origin"] != OriginGoBinary {
		t.Errorf("located at %q, origin %q; want the binary", got.Location.FilePath, got.Metadata["package_origin"])
	}
	if got.Metadata["applicability"] != "undetermined" || got.Severity == findings.SeverityInfo {
		t.Errorf("applicability %q, severity %s: the source tree's link set decided a binary's advisory",
			got.Metadata["applicability"], got.Severity)
	}
}

// Anything that is not a Go executable contributes nothing and no error: text,
// a file that only starts like an executable, and one too small to be a Go
// binary are all silently skipped, because nearly every file in a tree is one
// of them.
func TestNonGoFilesAreNotInventoried(t *testing.T) {
	dir := t.TempDir()
	big := strings.Repeat("x", minGoBinarySize)
	cases := map[string][]byte{
		"notes.txt":   []byte(big),
		"fake-elf":    append([]byte("\x7fELF"), big...),
		"fake-macho":  append([]byte{0xcf, 0xfa, 0xed, 0xfe}, big...),
		"fake-pe.exe": append([]byte("MZ"), big...),
		"tiny-elf":    []byte("\x7fELF tiny"),
	}
	var arts []discovery.Artifact
	for name, data := range cases {
		p := filepath.Join(dir, name)
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		arts = append(arts, discovery.Artifact{Path: name, AbsPath: p, Type: discovery.Unknown, Size: int64(len(data))})
	}
	inv, _, err := NewAnalyzer(WithOSVDisabled()).ScanArtifacts(context.Background(), arts)
	if err != nil {
		t.Fatal(err)
	}
	if n := len(inv.Packages()); n != 0 {
		t.Errorf("%d packages from files that are not Go binaries: %+v", n, inv.Packages())
	}
}

// A binary's modules are not judged against the source tree's import graph:
// what this repository's go.mod links says nothing about what a binary built
// elsewhere links. Applicability for them stays undetermined, with the reason.
func TestGoBinaryApplicabilityDoesNotBorrowTheSourceTree(t *testing.T) {
	pkg := Package{Name: "golang.org/x/text", Version: "v0.3.0", Ecosystem: "go", Origin: OriginGoBinary}
	ov := &osvVuln{ID: "GO-2026-0001"}
	ov.Affected = append(ov.Affected, osvAffected{})
	ov.Affected[0].Package.Name = "golang.org/x/text"
	ov.Affected[0].EcosystemSpecific.Imports = []osvImport{{Path: "golang.org/x/text/language"}}
	// The source tree provably does not link the affected package; a check
	// against it would refute the advisory for the binary too.
	linked := map[string]struct{}{"example.com/other": {}}
	v := applicabilityFor(pkg, ov, linked, true, &sourceImports{}, nil, "")
	if v.Outcome != "undetermined" {
		t.Errorf("binary package judged by the source tree: %+v", v)
	}
}
