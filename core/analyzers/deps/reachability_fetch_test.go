package deps

import (
	"archive/zip"
	"bytes"
	"context"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// The module the fixture depends on. Its root package imports a second one, so
// a link set that stops at the direct import is visibly short.
const (
	fetchDepModule  = "example.test/dep"
	fetchDepVersion = "v1.0.0"
	fetchDepInner   = fetchDepModule + "/inner"
)

// fileProxy writes a GOPROXY that serves fetchDepModule from disk and returns
// its URL. The go command reads a file:// proxy with no network at all, which
// is what lets these tests say what a cold module cache does.
func fileProxy(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, filepath.FromSlash(fetchDepModule), "@v")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	gomod := "module " + fetchDepModule + "\n\ngo 1.22\n"
	prefix := fetchDepModule + "@" + fetchDepVersion + "/"
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for name, content := range map[string]string{
		"go.mod":         gomod,
		"dep.go":         "package dep\n\nimport \"" + fetchDepInner + "\"\n\nfunc Name() string { return inner.Name() }\n",
		"inner/inner.go": "package inner\n\nfunc Name() string { return \"inner\" }\n",
	} {
		w, err := zw.Create(prefix + name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := w.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string][]byte{
		"list":                    []byte(fetchDepVersion + "\n"),
		fetchDepVersion + ".info": []byte(`{"Version":"` + fetchDepVersion + `","Time":"2024-01-01T00:00:00Z"}`),
		fetchDepVersion + ".mod":  []byte(gomod),
		fetchDepVersion + ".zip":  buf.Bytes(),
	} {
		if err := os.WriteFile(filepath.Join(dir, name), content, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	p := filepath.ToSlash(root)
	if !strings.HasPrefix(p, "/") {
		p = "/" + p // a Windows drive path
	}
	return "file://" + p
}

// moduleCache returns an empty module cache that the test removes afterwards.
// The go command writes its cache read-only, which t.TempDir cannot delete.
func moduleCache(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Cleanup(func() {
		_ = filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
			if err == nil && d.IsDir() {
				_ = os.Chmod(p, 0o755) //nolint:gosec // a test's own temp directory
			}
			return nil
		})
	})
	return dir
}

// moduleNeedingDep writes a module whose main package imports fetchDepModule,
// with the go.sum a read-only build needs, and returns its directory. The go.sum
// is produced against a module cache of its own, so the caller's starts cold.
func moduleNeedingDep(t *testing.T, proxy string) string {
	t.Helper()
	dir := t.TempDir()
	for name, content := range map[string]string{
		"go.mod":  "module example.test/app\n\ngo 1.22\n\nrequire " + fetchDepModule + " " + fetchDepVersion + "\n",
		"main.go": "package main\n\nimport \"" + fetchDepModule + "\"\n\nfunc main() { _ = dep.Name() }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cmd := exec.Command("go", "mod", "download", fetchDepModule)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOPROXY="+proxy, "GOMODCACHE="+moduleCache(t), "GOFLAGS=-mod=mod", "GOSUMDB=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go mod download: %v\n%s", err, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "go.sum")); err != nil {
		t.Fatalf("setup produced no go.sum: %v", err)
	}
	return dir
}

func fetchTestEnv(t *testing.T, proxy string) {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}
	t.Setenv("GOMODCACHE", moduleCache(t))
	t.Setenv("GOPROXY", proxy)
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOFLAGS", "")
}

// With a dependency's module neither cached nor fetchable, `go list -deps -e`
// exits 0 and prints the packages it could load: the direct import, and nothing
// the missing module imports in turn. That short list used to be returned as
// the build's whole link set, so an advisory for a package reached only through
// the missing module was answered "the build does not link it" and dropped to
// info. A link set the go command could not finish is unknown.
func TestGoImportedPackages_UnresolvedModuleIsUnknown(t *testing.T) {
	proxy := fileProxy(t)
	fetchTestEnv(t, proxy)
	dir := moduleNeedingDep(t, proxy)
	t.Setenv("GOPROXY", "off")

	pkgs, ok, fetched := goImportedPackages(context.Background(), dir)
	if ok {
		_, inner := pkgs[fetchDepInner]
		t.Errorf("ok = true with a module the go command could not load (%d packages, %s present: %v); want unknown",
			len(pkgs), fetchDepInner, inner)
	}
	if len(fetched) != 0 {
		t.Errorf("fetched = %q with GOPROXY=off; nothing can have been fetched", fetched)
	}
}

// A cold module cache with a reachable proxy: the go command fetches what it
// needs, the link set is whole, and the caller is told where the go command was
// allowed to go, because that is a request the scan made.
func TestGoImportedPackages_ColdCacheFetchesAndSaysSo(t *testing.T) {
	proxy := fileProxy(t)
	fetchTestEnv(t, proxy)
	dir := moduleNeedingDep(t, proxy)

	pkgs, ok, fetched := goImportedPackages(context.Background(), dir)
	if !ok {
		t.Fatal("ok = false although the proxy serves the module")
	}
	for _, want := range []string{"example.test/app", fetchDepModule, fetchDepInner} {
		if _, found := pkgs[want]; !found {
			t.Errorf("link set lacks %s", want)
		}
	}
	if len(fetched) != 1 || fetched[0] != proxy {
		t.Errorf("fetched = %q, want the proxy the go command used (%s)", fetched, proxy)
	}

	// The same build again: everything is in the module cache now, so the go
	// command needs nothing from the proxy and the scan made no request.
	pkgs, ok, fetched = goImportedPackages(context.Background(), dir)
	if !ok {
		t.Fatal("second run: ok = false")
	}
	if _, found := pkgs[fetchDepInner]; !found {
		t.Errorf("second run: link set lacks %s", fetchDepInner)
	}
	if len(fetched) != 0 {
		t.Errorf("second run: fetched = %q, want nothing: the module cache answered", fetched)
	}
}

func TestGoProxySources(t *testing.T) {
	tests := []struct {
		goproxy string
		want    []string
	}{
		{"https://proxy.golang.org,direct", []string{"https://proxy.golang.org", "direct"}},
		{"https://user:secret@proxy.corp.example/go|direct", []string{"https://proxy.corp.example", "direct"}},
		{"off", nil},
		{"", nil},
		{"https://proxy.golang.org,off", []string{"https://proxy.golang.org"}},
		{"file:///srv/goproxy", []string{"file:///srv/goproxy"}},
	}
	for _, tc := range tests {
		got := goProxySources(tc.goproxy)
		if strings.Join(got, " ") != strings.Join(tc.want, " ") {
			t.Errorf("goProxySources(%q) = %q, want %q", tc.goproxy, got, tc.want)
		}
	}
}
