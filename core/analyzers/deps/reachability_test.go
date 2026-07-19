package deps

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestGoAffectedImports(t *testing.T) {
	v := &osvVuln{
		ID: "GO-2026-5932",
		Affected: []osvAffected{{
			Package: osvPackage{Name: "golang.org/x/crypto", Ecosystem: "Go"},
			EcosystemSpecific: osvEcosystemSpecific{Imports: []osvImport{
				{Path: "golang.org/x/crypto/openpgp"},
				{Path: "golang.org/x/crypto/openpgp/packet"},
			}},
		}},
	}
	got := goAffectedImports(v, "golang.org/x/crypto")
	if len(got) != 2 || got[0] != "golang.org/x/crypto/openpgp" {
		t.Fatalf("got %+v", got)
	}
	// A different module in the same advisory must not match.
	if other := goAffectedImports(v, "golang.org/x/net"); len(other) != 0 {
		t.Errorf("expected no imports for a non-matching module, got %+v", other)
	}
}

func TestGoVulnReachable(t *testing.T) {
	linked := map[string]struct{}{
		"golang.org/x/crypto/chacha20":      {},
		"golang.org/x/crypto/cryptobyte":    {},
		"github.com/example/app/internal/x": {},
	}

	tests := []struct {
		name                 string
		affected             []string
		linked               map[string]struct{}
		known                bool
		wantReach, wantDeter bool
	}{
		{
			// The real GO-2026-5932 case: openpgp is not linked.
			name:      "affected package not linked",
			affected:  []string{"golang.org/x/crypto/openpgp"},
			linked:    linked,
			known:     true,
			wantReach: false, wantDeter: true,
		},
		{
			name:      "affected package is linked",
			affected:  []string{"golang.org/x/crypto/chacha20"},
			linked:    linked,
			known:     true,
			wantReach: true, wantDeter: true,
		},
		{
			// Advisories cover subpackages of the path they name.
			name:      "subpackage of an affected path counts as linked",
			affected:  []string{"golang.org/x/crypto"},
			linked:    linked,
			known:     true,
			wantReach: true, wantDeter: true,
		},
		{
			// Fail open: no import metadata means no conclusion.
			name:      "advisory lists no import paths",
			affected:  nil,
			linked:    linked,
			known:     true,
			wantReach: true, wantDeter: false,
		},
		{
			// Fail open: toolchain unavailable means no conclusion.
			name:      "linked set unknown",
			affected:  []string{"golang.org/x/crypto/openpgp"},
			linked:    nil,
			known:     false,
			wantReach: true, wantDeter: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reach, deter := goVulnReachable(tt.affected, tt.linked, tt.known)
			if reach != tt.wantReach || deter != tt.wantDeter {
				t.Errorf("got (reachable=%v, determined=%v), want (%v, %v)",
					reach, deter, tt.wantReach, tt.wantDeter)
			}
		})
	}
}

func TestGoImportedPackages(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	dir := t.TempDir()
	write := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/reachtest\n\ngo 1.24\n")
	write("main.go", "package main\n\nimport \"strings\"\n\nfunc main() { _ = strings.TrimSpace(\"x\") }\n")

	pkgs, ok := goImportedPackages(context.Background(), dir)
	if !ok {
		t.Fatal("expected go list to succeed")
	}
	if _, found := pkgs["strings"]; !found {
		t.Errorf("expected 'strings' among linked packages, got %d packages", len(pkgs))
	}
	if _, found := pkgs["example.com/reachtest"]; !found {
		t.Errorf("expected the main package among linked packages")
	}
}

// A directory that is not a Go module must degrade to "unknown" rather than
// erroring the scan.
func TestGoImportedPackages_NotAModule(t *testing.T) {
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	if _, ok := goImportedPackages(context.Background(), t.TempDir()); ok {
		t.Error("expected ok=false for a non-module directory")
	}
}
