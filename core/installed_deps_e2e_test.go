package core

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

const rootLock = `{"name":"app","lockfileVersion":3,"packages":{"":{"name":"app"},"node_modules/express":{"version":"4.21.2"}}}`

// An installed dependency ships its own lockfile (combined-stream publishes a
// yarn.lock). That file describes the dependency's dev-time pins, not what this
// project resolved: the project's own lockfile already names every installed
// package. Reading it as a project manifest reported a vendored package's
// vulnerabilities as the user's, and a package-manager run (the fix tool's own
// `npm install`) made them appear out of nowhere.
func TestInstalledDependencyLockfileIsNotAProjectManifest(t *testing.T) {
	root := t.TempDir()
	write := func(rel, body string) {
		t.Helper()
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("package-lock.json", rootLock)
	write("node_modules/express/package.json", `{"name":"express","version":"4.21.2"}`)
	write("node_modules/combined-stream/yarn.lock", "# yarn lockfile v1\n\n\nlodash@4.17.4:\n  version \"4.17.4\"\n")
	write("node_modules/combined-stream/package-lock.json", `{"packages":{"node_modules/minimist":{"version":"0.0.8"}}}`)

	res, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	var names []string
	for _, p := range res.Inventory.Packages() {
		names = append(names, p.Name)
		if p.Name == "lodash" || p.Name == "minimist" {
			t.Errorf("package %q came from a dependency's own lockfile under node_modules, not from this project", p.Name)
		}
	}
	if len(names) != 1 || names[0] != "express" {
		t.Errorf("inventory = %v, want exactly the root lockfile's [express]", names)
	}
}

// The exemption is for manifests only. A secret committed inside an installed
// package is still a real finding, and a vendored directory the user checked in
// is still scanned.
func TestInstalledDependencyDirIsStillScannedForSecrets(t *testing.T) {
	root := t.TempDir()
	dir := filepath.Join(root, "node_modules", "leaky")
	if err := os.MkdirAll(dir, 0o750); err != nil {
		t.Fatal(err)
	}
	key := "AKIA" + "IOSFODNN7EXAMPLQ"
	if err := os.WriteFile(filepath.Join(dir, "config.js"), []byte("const k = '"+key+"';\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	res, err := RunScanContext(context.Background(), root, ScanOptions{Offline: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	for _, f := range res.Findings.ActiveFindings() {
		if f.Location.FilePath == "node_modules/leaky/config.js" {
			return
		}
	}
	t.Fatalf("a credential under node_modules was not reported; findings: %d", len(res.Findings.ActiveFindings()))
}
