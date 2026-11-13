package deps

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// `npm install pkg@fixed` for a package the project does not list adds it as a
// new direct dependency and leaves the copy its parent resolves where it was:
// the finding stays and the lockfile now looks fixed. minimatch in nox's own VS
// Code extension came with exactly that command. A transitive npm finding
// carries the answer nox fix plan gives: the parent that holds it and the
// overrides entry, or `npm update` when every parent allows the fix.
func TestTransitiveNPMFindingOffersNoInstallCommand(t *testing.T) {
	t.Parallel()
	srv := fakeOSV(t,
		map[string][]string{"minimatch": {"GHSA-mm"}},
		map[string]string{"GHSA-mm": `{"id":"GHSA-mm","summary":"amplification",
			"affected":[{"package":{"name":"minimatch","ecosystem":"npm"},
			"ranges":[{"type":"SEMVER","events":[{"introduced":"7.0.0"},{"fixed":"11.0.1"}]}]}]}`})
	defer srv.Close()

	const heldLock = `{"packages":{
"":{"dependencies":{"vscode-languageclient":"^10.1.2"}},
"node_modules/vscode-languageclient":{"version":"10.1.2","dependencies":{"minimatch":"^10.2.6"}},
"node_modules/minimatch":{"version":"10.2.6"}}}`
	const movableLock = `{"packages":{
"":{"dependencies":{"glob":"^12.0.0"}},
"node_modules/glob":{"version":"12.0.0","dependencies":{"minimatch":"^10.2.6 || ^11.0.0"}},
"node_modules/minimatch":{"version":"10.2.6"}}}`
	const bareLock = `{"packages":{"node_modules/minimatch":{"version":"10.2.6"}}}`
	for name, tc := range map[string]struct {
		lock, manifest string
		wantCommand    string
		wantNote       []string // empty: no note
	}{
		// The finding names what nox fix plan names: the parent and the entry.
		"transitive, held by its parent": {heldLock, `{"dependencies":{"vscode-languageclient":"^10.1.2"}}`, "",
			[]string{"vscode-languageclient@10.1.2 requires minimatch ^10.2.6", `"overrides": { "minimatch": "11.0.1" }`}},
		// Every parent allows the fix: npm update moves it, as apply runs.
		"transitive, every parent allows": {movableLock, `{"dependencies":{"glob":"^12.0.0"}}`, "npm update --ignore-scripts minimatch", nil},
		// A listed package keeps its section and specifier style.
		"direct":     {bareLock, `{"dependencies":{"minimatch":"^10.2.6"}}`, "npm install --ignore-scripts --save-prefix=^ minimatch@11.0.1", nil},
		"direct dev": {bareLock, `{"devDependencies":{"minimatch":"~10.2.6"}}`, "npm install --ignore-scripts --save-dev --save-prefix=~ minimatch@11.0.1", nil},
		// No package.json: what apply would run there, and no transitive claim.
		"no manifest beside": {bareLock, "", "npm update --ignore-scripts minimatch", nil},
	} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			lock := tc.lock
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
			if cmd := f.Metadata["remediation_command"]; cmd != tc.wantCommand {
				t.Errorf("command = %q, want %q", cmd, tc.wantCommand)
			}
			note := f.Metadata["remediation_note"]
			if len(tc.wantNote) == 0 && note != "" {
				t.Errorf("unexpected note %q", note)
			}
			for _, want := range tc.wantNote {
				if !strings.Contains(note, want) {
					t.Errorf("note %q does not name %q", note, want)
				}
			}
			if len(tc.wantNote) > 0 && f.Metadata["remediation_scope"] != "transitive" {
				t.Errorf("remediation_scope = %q, want transitive", f.Metadata["remediation_scope"])
			}
		})
	}
}

// A Python finding offers the pin edit apply makes in its own file, or no
// command and the resolver's own when the file is a lockfile.
func TestPyPIFindingNamesTheEditOrTheResolver(t *testing.T) {
	t.Parallel()
	srv := fakeOSV(t,
		map[string][]string{"requests": {"GHSA-rq"}},
		map[string]string{"GHSA-rq": `{"id":"GHSA-rq","summary":"leak",
			"affected":[{"package":{"name":"requests","ecosystem":"PyPI"},
			"ranges":[{"type":"ECOSYSTEM","events":[{"introduced":"0"},{"fixed":"2.32.0"}]}]}]}`})
	defer srv.Close()
	for file, tc := range map[string]struct{ body, command, note string }{
		"requirements.txt": {"requests==2.31.0\n", "set requests==2.32.0 in requirements.txt", ""},
		"poetry.lock":      {"[[package]]\nname = \"requests\"\nversion = \"2.31.0\"\n", "", "poetry update requests"},
	} {
		t.Run(file, func(t *testing.T) {
			dir := t.TempDir()
			p := filepath.Join(dir, file)
			if err := os.WriteFile(p, []byte(tc.body), 0o644); err != nil {
				t.Fatal(err)
			}
			a := NewAnalyzer(WithOSVBaseURL(srv.URL), WithHTTPClient(srv.Client()))
			_, fs, err := a.ScanArtifacts(context.Background(), []discovery.Artifact{{
				Path: file, AbsPath: p, Type: discovery.Lockfile, Size: int64(len(tc.body)),
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
			if got := f.Metadata["remediation_command"]; got != tc.command {
				t.Errorf("command = %q, want %q", got, tc.command)
			}
			if tc.note != "" && !strings.Contains(f.Metadata["remediation_note"], tc.note) {
				t.Errorf("note = %q, want it to name %q", f.Metadata["remediation_note"], tc.note)
			}
		})
	}
}
