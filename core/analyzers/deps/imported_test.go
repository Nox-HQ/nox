package deps

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox-core/vulnsource"
	"github.com/nox-hq/nox/core/discovery"
)

// goAppImporting writes a module requiring golang.org/x/text whose main.go
// imports the given paths, and returns the artifacts a scan would discover:
// the go.mod and, when there is any, the source file.
func goAppImporting(t *testing.T, imports ...string) []discovery.Artifact {
	t.Helper()
	// The module is never downloaded: the toolchain's answer is not what this
	// tests, and a fixture that needed the network would quietly stop running.
	t.Setenv("GOPROXY", "off")
	t.Setenv("GOFLAGS", "-mod=mod")
	dir := t.TempDir()
	gomod := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(gomod, []byte("module example.com/app\n\ngo 1.21\n\nrequire golang.org/x/text v0.3.7\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	arts := []discovery.Artifact{{Path: "go.mod", AbsPath: gomod, Type: discovery.Lockfile}}
	if imports == nil {
		return arts
	}
	src := "package main\n\nimport (\n"
	for _, p := range imports {
		src += "\t_ \"" + p + "\"\n"
	}
	src += ")\n\nfunc main() {}\n"
	main := filepath.Join(dir, "main.go")
	if err := os.WriteFile(main, []byte(src), 0o600); err != nil {
		t.Fatal(err)
	}
	return append(arts, discovery.Artifact{Path: "main.go", AbsPath: main, Type: discovery.Source})
}

// Proposition: a Go dependency finding records whether the project's own source
// imports the module, through the analyzer's real path, and records nothing when
// no Go source was read. The fact changes no verdict.
func TestGoFindingRecordsWhetherTheProjectImportsTheModule(t *testing.T) {
	src := &stubSource{name: "stub", records: map[string][]vulnsource.Record{
		"golang.org/x/text": {{ID: "STUB-TEXT", Summary: "no import metadata",
			Affected: []vulnsource.Affected{{Package: vulnsource.Package{Name: "golang.org/x/text", Ecosystem: "Go"}}}}},
	}}
	for name, c := range map[string]struct {
		imports []string
		want    string
	}{
		"imports a package of the module": {[]string{"fmt", "golang.org/x/text/language"}, "true"},
		"imports something else":          {[]string{"fmt", "golang.org/x/textual"}, "false"},
		"no Go source read":               {nil, ""},
	} {
		_, fs, err := NewAnalyzer(WithSource(src)).ScanArtifacts(context.Background(), goAppImporting(t, c.imports...))
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		f := vulnFinding(t, fs)
		got, present := f.Metadata["dependency_imported"]
		if got != c.want || present != (c.want != "") {
			t.Errorf("%s: dependency_imported = %q (present %v), want %q", name, got, present, c.want)
		}
		if f.Metadata["applicability"] != "undetermined" {
			t.Errorf("%s: applicability = %q; the import fact must not decide anything", name, f.Metadata["applicability"])
		}
	}
}
