package core

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// feedProbe is a service that publishes no feed and records what it was asked.
func feedProbe(t *testing.T) (srv *httptest.Server, asked func() []string) {
	t.Helper()
	var mu sync.Mutex
	var paths []string
	srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []string {
		mu.Lock()
		defer mu.Unlock()
		return append([]string(nil), paths...)
	}
}

// projectWithoutDependencies has one source file and no manifest, so a scan of
// it has no dependency to look up and no base image to pull.
func projectWithoutDependencies(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	files["app.py"] = "import os\n\nprint(os.getcwd())\n"
	for name, content := range files {
		p := filepath.Join(dir, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return dir
}

// A default scan asks the intelligence service for its signed slopsquat feed
// whether or not the project has a dependency. The dependency lookup is the
// only request the scan used to account for, so a project with none was
// scanned "with nothing sent" while a request left the machine. The result
// names every feed the scan requested.
func TestScan_ReportsTheFeedsItRequested(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, asked := feedProbe(t)
	t.Setenv(IntelligenceEndpointEnv, srv.URL)
	dir := projectWithoutDependencies(t, map[string]string{})

	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if got := asked(); len(got) == 0 {
		t.Fatal("the scan asked the service nothing; this test no longer exercises a feed request")
	}
	want := srv.URL + "/v1/feeds/slopsquat"
	if len(res.FeedsRequested) != 1 || res.FeedsRequested[0] != want {
		t.Errorf("FeedsRequested = %q, want [%s]; the service was asked %q", res.FeedsRequested, want, asked())
	}
}

// An MCP server launched from a registry adds the MCP advisory feed.
func TestScan_ReportsTheMCPFeedRequest(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, _ := feedProbe(t)
	t.Setenv(IntelligenceEndpointEnv, srv.URL)
	dir := projectWithoutDependencies(t, map[string]string{
		".mcp.json": `{"mcpServers":{"files":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.0.0"]}}}`,
	})

	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	want := []string{srv.URL + "/v1/feeds/mcp", srv.URL + "/v1/feeds/slopsquat"}
	if len(res.FeedsRequested) != 2 || res.FeedsRequested[0] != want[0] || res.FeedsRequested[1] != want[1] {
		t.Errorf("FeedsRequested = %q, want %q", res.FeedsRequested, want)
	}
}

// Every way of keeping the scan off the network keeps it off for the feeds too,
// the one .nox.yaml names by URL included, and then no feed is reported as
// requested. The notices say "--offline or scan.osv.disabled: true makes no
// network request" without qualification, so there must be no exception.
func TestScan_NoFeedRequestWhenTheNetworkIsOff(t *testing.T) {
	mcp := `{"mcpServers":{"files":{"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@1.0.0"]}}}`
	switches := []struct {
		name string
		osv  string
		opts ScanOptions
	}{
		{name: "--offline", opts: ScanOptions{Offline: true}},
		{name: "--no-osv", opts: ScanOptions{DisableOSV: true}},
		{name: "scan.osv.disabled", osv: "  osv:\n    disabled: true\n"},
	}
	for _, sw := range switches {
		for _, feed := range []string{"the service's feed", "a feed named by URL"} {
			t.Run(sw.name+", "+feed, func(t *testing.T) {
				t.Setenv("HOME", t.TempDir())
				srv, asked := feedProbe(t)
				t.Setenv(IntelligenceEndpointEnv, srv.URL)
				noxYAML := "scan:\n" + sw.osv
				if feed == "a feed named by URL" {
					noxYAML += "  slop:\n    feed: " + srv.URL + "/mirror/slopsquat.json\n"
				}
				files := map[string]string{".mcp.json": mcp}
				if noxYAML != "scan:\n" {
					files[".nox.yaml"] = noxYAML
				}
				res, err := RunScanWithOptions(projectWithoutDependencies(t, files), sw.opts)
				if err != nil {
					t.Fatalf("scan failed: %v", err)
				}
				if got := asked(); len(got) != 0 {
					t.Errorf("the service was asked %q", got)
				}
				if len(res.FeedsRequested) != 0 {
					t.Errorf("FeedsRequested = %q, want none", res.FeedsRequested)
				}
			})
		}
	}
}

// A feed .nox.yaml names by URL is a request to a host of the operator's
// choosing; it is reported like the service's own, without the credentials a
// URL may carry.
func TestScan_ReportsAFeedNamedByURL(t *testing.T) {
	t.Setenv("HOME", t.TempDir())
	srv, asked := feedProbe(t)
	t.Setenv(IntelligenceEndpointEnv, srv.URL)
	withCredentials := "http://reader:hunter2@" + srv.Listener.Addr().String() + "/mirror/slopsquat.json?token=abc"
	dir := projectWithoutDependencies(t, map[string]string{
		".nox.yaml": "scan:\n  slop:\n    feed: " + withCredentials + "\n",
	})

	res, err := RunScanWithOptions(dir, ScanOptions{})
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if got := asked(); len(got) != 1 || got[0] != "/mirror/slopsquat.json" {
		t.Fatalf("the service was asked %q, want the one configured feed", got)
	}
	want := srv.URL + "/mirror/slopsquat.json"
	if len(res.FeedsRequested) != 1 || res.FeedsRequested[0] != want {
		t.Errorf("FeedsRequested = %q, want [%s]", res.FeedsRequested, want)
	}
}
