package deps

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// `npm install pkg@fixed` for a package the project does not list adds it as a
// new direct dependency and leaves the copy its parent resolves where it was:
// the finding stays and the lockfile now looks fixed. minimatch in nox's own VS
// Code extension came with exactly that command. A transitive npm finding
// carries no install command; it says what decides the move instead.
func TestTransitiveNPMFindingOffersNoInstallCommand(t *testing.T) {
	t.Parallel()
	srv := fakeOSV(t,
		map[string][]string{"minimatch": {"GHSA-mm"}},
		map[string]string{"GHSA-mm": `{"id":"GHSA-mm","summary":"amplification",
			"affected":[{"package":{"name":"minimatch","ecosystem":"npm"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"7.0.0"},{"fixed":"11.0.1"}]}]}]}`})
	defer srv.Close()

	for name, tc := range map[string]struct {
		manifest    string
		wantCommand bool
	}{
		"transitive":         {`{"dependencies":{"vscode-languageclient":"^10.1.2"}}`, false},
		"direct":             {`{"dependencies":{"minimatch":"^10.2.6"}}`, true},
		"direct dev":         {`{"devDependencies":{"minimatch":"^10.2.6"}}`, true},
		"no manifest beside": {"", true}, // nothing is claimed about a manifest nox did not see
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			lock := `{"packages":{"node_modules/minimatch":{"version":"10.2.6"}}}`
			lockPath := filepath.Join(dir, "package-lock.json")
			if err := os.WriteFile(lockPath, []byte(lock), 0o644); err != nil {
				t.Fatal(err)
			}
			if tc.manifest != "" {
				if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte(tc.manifest), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			a := NewAnalyzer(WithOSVBaseURL(srv.URL), WithHTTPClient(srv.Client()))
			_, fs, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{{
				Path: "package-lock.json", AbsPath: lockPath, Type: discovery.Lockfile, Size: int64(len(lock)),
			}})
			if err != nil {
				t.Fatal(err)
			}
			var f *findings.Finding
			for _, x := range fs.Findings() {
				if x.RuleID == "VULN-001" {
					f = &x
				}
			}
			if f == nil {
				t.Fatal("no VULN-001")
			}
			if f.Metadata["fixed_in"] != "11.0.1" {
				t.Errorf("fixed_in = %q; the fixed version is a fact either way", f.Metadata["fixed_in"])
			}
			cmd := f.Metadata["remediation_command"]
			if tc.wantCommand && cmd != "npm install minimatch@11.0.1" {
				t.Errorf("command = %q, want the install command", cmd)
			}
			if !tc.wantCommand {
				if cmd != "" {
					t.Errorf("a transitive package got the install command %q", cmd)
				}
				if f.Metadata["remediation_scope"] != "transitive" || f.Metadata["remediation_note"] == "" {
					t.Errorf("transitive finding does not say what decides the move: %v", f.Metadata)
				}
			}
		})
	}
}
