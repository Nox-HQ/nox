package deps

import (
	"sort"
	"testing"
)

func TestParseGoMod(t *testing.T) {
	content := []byte(`module example.com/myapp

go 1.24

require (
	github.com/stretchr/testify v1.8.0
	golang.org/x/net v0.56.0 // indirect
)

require golang.org/x/crypto v0.53.0
`)

	pkgs, err := parseGoMod(content)
	if err != nil {
		t.Fatalf("parseGoMod returned error: %v", err)
	}

	if len(pkgs) != 3 {
		t.Fatalf("expected 3 packages, got %d: %+v", len(pkgs), pkgs)
	}

	sort.Slice(pkgs, func(i, j int) bool { return pkgs[i].Name < pkgs[j].Name })

	expected := []Package{
		{Name: "github.com/stretchr/testify", Version: "v1.8.0", Ecosystem: "go"},
		{Name: "golang.org/x/crypto", Version: "v0.53.0", Ecosystem: "go"},
		{Name: "golang.org/x/net", Version: "v0.56.0", Ecosystem: "go"},
	}
	for i, want := range expected {
		if pkgs[i] != want {
			t.Errorf("package %d: got %+v, want %+v", i, pkgs[i], want)
		}
	}
}

// The main module is not a dependency and must never be reported.
func TestParseGoMod_ExcludesMainModule(t *testing.T) {
	pkgs, err := parseGoMod([]byte("module example.com/myapp\n\ngo 1.24\n"))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %+v", pkgs)
	}
}

// A replace directive redirects to a different module and/or version; the
// version actually built is the replacement's, so that is what must be scanned.
func TestParseGoMod_AppliesReplace(t *testing.T) {
	content := []byte(`module example.com/myapp

go 1.24

require (
	golang.org/x/net v0.20.0
	example.com/vendored v1.0.0
)

replace golang.org/x/net => golang.org/x/net v0.56.0

replace example.com/vendored => ./internal/vendored
`)

	pkgs, err := parseGoMod(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// The local filesystem replacement is not a fetched module, so it drops out.
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %+v", pkgs)
	}
	want := Package{Name: "golang.org/x/net", Version: "v0.56.0", Ecosystem: "go"}
	if pkgs[0] != want {
		t.Errorf("got %+v, want %+v", pkgs[0], want)
	}
}

// A version-specific replace applies only to that version.
func TestParseGoMod_VersionedReplace(t *testing.T) {
	content := []byte(`module example.com/myapp

go 1.24

require golang.org/x/text v0.3.7

replace golang.org/x/text v0.3.7 => golang.org/x/text v0.3.8
`)

	pkgs, err := parseGoMod(content)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Version != "v0.3.8" {
		t.Fatalf("expected x/text v0.3.8, got %+v", pkgs)
	}
}

func TestParseGoMod_EmptyInput(t *testing.T) {
	pkgs, err := parseGoMod([]byte(""))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
}

func TestCompareGoVersions(t *testing.T) {
	tests := []struct {
		a, b string
		want int // -1 a<b, 0 equal, 1 a>b
	}{
		{"v1.2.3", "v1.2.4", -1},
		{"v1.2.3", "v1.2.3", 0},
		{"v1.10.0", "v1.9.0", 1},
		{"v2.0.0", "v10.0.0", -1},
		// A release outranks its own prerelease.
		{"v1.2.3", "v1.2.3-rc1", 1},
		// Pseudo-versions order by the embedded timestamp.
		{"v0.0.0-20190620200207-3b0461eec859", "v0.0.0-20220225172249-27dd8689420f", -1},
		// A tagged release outranks a v0.0.0 pseudo-version.
		{"v0.56.0", "v0.0.0-20190620200207-3b0461eec859", 1},
	}
	for _, tt := range tests {
		if got := compareGoVersions(tt.a, tt.b); got != tt.want {
			t.Errorf("compareGoVersions(%q,%q) = %d, want %d", tt.a, tt.b, got, tt.want)
		}
	}
}

// resolveGoPackages combines both files: go.mod is authoritative for the
// modules it names, and go.sum supplies modules that pruning omitted from
// go.mod but that the build still links.
func TestResolveGoPackages_RecoversPrunedTransitives(t *testing.T) {
	goMod := []byte(`module example.com/myapp

go 1.24

require golang.org/x/net v0.56.0
`)
	// x/net appears at an old graph version too (must NOT win — go.mod decides),
	// while yaml.v2 is built but pruned out of go.mod (must be recovered).
	goSum := []byte(`golang.org/x/net v0.0.0-20190620200207-3b0461eec859 h1:a=
golang.org/x/net v0.56.0 h1:b=
gopkg.in/yaml.v2 v2.2.2 h1:c=
gopkg.in/yaml.v2 v2.2.2/go.mod h1:d=
`)

	pkgs, err := resolveGoPackages(goMod, goSum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	if got["golang.org/x/net"] != "v0.56.0" {
		t.Errorf("go.mod must win for x/net, got %q", got["golang.org/x/net"])
	}
	if got["gopkg.in/yaml.v2"] != "v2.2.2" {
		t.Errorf("pruned transitive yaml.v2 not recovered, got %q", got["gopkg.in/yaml.v2"])
	}
	if len(pkgs) != 2 {
		t.Fatalf("expected exactly 2 packages, got %+v", pkgs)
	}
}

// A go.sum entry with only a "/go.mod" hash means Go fetched the module's
// metadata to compute the graph but never downloaded its source, so none of its
// code is in the build. Such a module must not be reported.
func TestResolveGoPackages_IgnoresGoModHashOnlyEntries(t *testing.T) {
	goMod := []byte("module example.com/myapp\n\ngo 1.24\n")
	goSum := []byte(`golang.org/x/crypto v0.0.0-20190308221718-c2843e01d9a2/go.mod h1:a=
gopkg.in/yaml.v2 v2.2.2 h1:b=
gopkg.in/yaml.v2 v2.2.2/go.mod h1:c=
`)

	pkgs, err := resolveGoPackages(goMod, goSum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected only the source-hashed module, got %+v", pkgs)
	}
	if pkgs[0].Name != "gopkg.in/yaml.v2" {
		t.Errorf("got %q, want gopkg.in/yaml.v2", pkgs[0].Name)
	}
}

// For a module absent from go.mod, MVS selects the maximum required version,
// so the highest version in go.sum is the best available estimate.
func TestResolveGoPackages_PicksMaxVersionForPrunedModule(t *testing.T) {
	goMod := []byte("module example.com/myapp\n\ngo 1.24\n")
	goSum := []byte(`gopkg.in/yaml.v2 v2.2.2 h1:a=
gopkg.in/yaml.v2 v2.4.0 h1:b=
gopkg.in/yaml.v2 v2.3.0 h1:c=
`)
	pkgs, err := resolveGoPackages(goMod, goSum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Version != "v2.4.0" {
		t.Fatalf("expected yaml.v2 v2.4.0, got %+v", pkgs)
	}
}

// A module replaced by a local filesystem path is not fetched, so it must not
// be resurrected from go.sum.
func TestResolveGoPackages_LocalReplaceStaysDropped(t *testing.T) {
	goMod := []byte(`module example.com/myapp

go 1.24

require example.com/vendored v1.0.0

replace example.com/vendored => ./internal/vendored
`)
	goSum := []byte("example.com/vendored v1.0.0 h1:a=\n")

	pkgs, err := resolveGoPackages(goMod, goSum)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("locally replaced module must not reappear, got %+v", pkgs)
	}
}

// go.sum is optional; a go.mod alone must still resolve.
func TestResolveGoPackages_NoGoSum(t *testing.T) {
	goMod := []byte("module example.com/myapp\n\ngo 1.24\n\nrequire golang.org/x/net v0.56.0\n")
	pkgs, err := resolveGoPackages(goMod, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(pkgs) != 1 || pkgs[0].Version != "v0.56.0" {
		t.Fatalf("expected x/net v0.56.0, got %+v", pkgs)
	}
}

// Regression test for the reason this parser exists: go.sum records the whole
// module graph, including versions MVS never selected, so scanning it reports
// vulnerabilities against code that is not built. go.mod carries the selected
// versions. See https://go.dev/ref/mod#go-sum-files.
func TestParseGoMod_SelectsBuiltVersionNotGraphVersion(t *testing.T) {
	// Mirrors a real case: the build uses x/net v0.56.0, while go.sum still
	// carries a 2019 pseudo-version from an older graph.
	goMod := []byte(`module example.com/myapp

go 1.24

require golang.org/x/net v0.56.0 // indirect
`)
	goSum := []byte(`golang.org/x/net v0.0.0-20190620200207-3b0461eec859 h1:x=
golang.org/x/net v0.0.0-20190620200207-3b0461eec859/go.mod h1:x=
golang.org/x/net v0.56.0 h1:y=
golang.org/x/net v0.56.0/go.mod h1:y=
`)

	modPkgs, err := parseGoMod(goMod)
	if err != nil {
		t.Fatalf("parseGoMod: %v", err)
	}
	sumPkgs, err := parseGoSum(goSum)
	if err != nil {
		t.Fatalf("parseGoSum: %v", err)
	}

	if len(modPkgs) != 1 || modPkgs[0].Version != "v0.56.0" {
		t.Fatalf("go.mod should yield only the built version, got %+v", modPkgs)
	}
	if len(sumPkgs) != 2 {
		t.Fatalf("expected go.sum to yield both graph versions, got %+v", sumPkgs)
	}
}
