package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/findings"
)

const mcpFeedTestdata = "mcpfeed/testdata/"

// feedProject writes a project with MCP servers and the config that pins the
// service's test key, and returns its root and the number of feed requests the
// test server saw.
func feedProject(t *testing.T, servers string, status int, feedBody []byte, withKey bool) (dir string, requests *atomic.Int32) {
	t.Helper()
	var n atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/feeds/mcp":
			n.Add(1)
			if status != http.StatusOK {
				w.WriteHeader(status)
				_, _ = w.Write([]byte(`{"error":"no MCP advisory feed has been published yet"}`))
				return
			}
			_, _ = w.Write(feedBody)
		case "/v1/feeds/mcp/status":
			_, _ = w.Write([]byte(`{"disabled_reason":"no feed signing key is configured"}`))
		default:
			_, _ = w.Write([]byte(`{"results":[]}`))
		}
	}))
	t.Cleanup(srv.Close)

	dir = t.TempDir()
	writeFile(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{`+servers+`}}`)
	key, err := os.ReadFile(mcpFeedTestdata + "pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	writeFile(t, filepath.Join(dir, "keys", "intel.pub.pem"), string(key))
	cfg := "scan:\n  intelligence:\n    endpoint: " + srv.URL + "\n    verify_against_osv: false\n"
	if withKey {
		cfg += "  mcp_feed:\n    signature_key_path: keys/intel.pub.pem\n    cache_dir: " + filepath.Join(dir, "cache") + "\n"
	}
	writeFile(t, filepath.Join(dir, ".nox.yaml"), cfg)
	return dir, &n
}

func feedDegradations(res *ScanResult) []Degradation {
	var out []Degradation
	for _, d := range res.Degradations {
		if d.Kind == degradeMCPFeed {
			out = append(out, d)
		}
	}
	return out
}

func feedFindings(res *ScanResult) []findings.Finding {
	var out []findings.Finding
	for _, f := range res.Findings.Findings() {
		if f.RuleID == MCPFeedRuleID {
			out = append(out, f)
		}
	}
	return out
}

const feedServers = `
  "fs":    {"command":"npx","args":["-y","@modelcontextprotocol/server-filesystem@2025.1.14","/"]},
  "fixed": {"command":"npx","args":["mcp-server-x@1.4.2"]},
  "old":   {"command":"npx","args":["mcp-server-x@1.4.1"]},
  "git":   {"command":"uvx","args":["mcp-server-git"]},
  "other": {"command":"npx","args":["left-pad@1.0.0"]},
  "local": {"command":"node","args":["./server.js"]}`

func TestMCPFeed_ReportsAdvisoriesThatCoverAPinnedVersion(t *testing.T) {
	body, err := os.ReadFile(mcpFeedTestdata + "feed.json")
	if err != nil {
		t.Fatal(err)
	}
	dir, _ := feedProject(t, feedServers, 200, body, true)
	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]findings.Finding{}
	for _, f := range feedFindings(res) {
		got[f.Metadata["server"]] = f
	}
	if len(got) != 3 || got["fs"].Metadata["match"] != "range" || got["old"].Metadata["match"] != "range" || got["git"].Metadata["match"] != "unpinned" {
		t.Fatalf("findings = %v", got)
	}
	// Not matched: a fixed version, a package the feed does not list, a server
	// that is not a registry package.
	for _, quiet := range []string{"fixed", "other", "local"} {
		if _, ok := got[quiet]; ok {
			t.Errorf("%s must not be reported", quiet)
		}
	}
	// The unpinned case is a lead, not a match: low confidence, info severity.
	if g := got["git"]; g.Severity != findings.SeverityInfo || g.Confidence != findings.ConfidenceLow || !strings.Contains(g.Message, "Cannot be checked") {
		t.Errorf("unpinned server = %s/%s %q", g.Severity, g.Confidence, g.Message)
	}
	// Never exploitability.
	if m := got["fs"].Message; !strings.Contains(m, "does not say your use of the server is exploitable") {
		t.Errorf("message reads as stronger than it is: %q", m)
	}
	if len(feedDegradations(res)) != 0 {
		t.Errorf("a clean check degrades nothing: %+v", feedDegradations(res))
	}
}

func TestMCPFeed_NoPublishedFeedSaysSoAndIsNotBlocking(t *testing.T) {
	dir, _ := feedProject(t, feedServers, 404, nil, true)
	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(feedFindings(res)) != 0 {
		t.Fatalf("an unavailable feed produced findings: %+v", feedFindings(res))
	}
	ds := feedDegradations(res)
	if len(ds) != 1 || !strings.Contains(ds[0].Detail, "not available") || !strings.Contains(ds[0].Detail, "no feed signing key is configured") ||
		!strings.Contains(ds[0].Impact, `not "no advisories"`) {
		t.Fatalf("degradation = %+v", ds)
	}
	if !ds[0].Advisory {
		t.Error("a service that has not published a feed is not the operator's to fix; it must not fail a build")
	}
}

func TestMCPFeed_AFeedThatDoesNotVerifyFailsClosedAndBlocks(t *testing.T) {
	good, _ := os.ReadFile(mcpFeedTestdata + "feed.json")
	bad := []byte(strings.Replace(string(good), "Directory escape", "Nothing to see", 1))
	dir, _ := feedProject(t, feedServers, 200, bad, true)
	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(feedFindings(res)) != 0 {
		t.Fatalf("a tampered feed was used: %+v", feedFindings(res))
	}
	ds := feedDegradations(res)
	if len(ds) != 1 || ds[0].Advisory || !strings.Contains(ds[0].Detail, "digest mismatch") {
		t.Fatalf("degradation = %+v", ds)
	}
}

func TestMCPFeed_WithoutAPinnedKeyTheFeedIsNotConsultedAndTheScanSaysSo(t *testing.T) {
	good, _ := os.ReadFile(mcpFeedTestdata + "feed.json")
	dir, requests := feedProject(t, feedServers, 200, good, false)
	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || len(feedFindings(res)) != 0 {
		t.Fatalf("an unpinned feed was consulted: requests=%d findings=%+v", requests.Load(), feedFindings(res))
	}
	ds := feedDegradations(res)
	if len(ds) != 1 || !ds[0].Advisory || !strings.Contains(ds[0].Detail, "no public key is pinned") {
		t.Fatalf("degradation = %+v", ds)
	}
}

// Quiet unless it has something to check, and offline-first.
func TestMCPFeed_QuietWithoutRegistryServersOrWhenOffline(t *testing.T) {
	good, _ := os.ReadFile(mcpFeedTestdata + "feed.json")
	dir, requests := feedProject(t, `"local":{"command":"node","args":["./s.js"]},"remote":{"url":"https://x.example/mcp"}`, 200, good, true)
	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || len(feedFindings(res)) != 0 || len(feedDegradations(res)) != 0 {
		t.Fatalf("nothing to check, yet requests=%d findings=%d degradations=%+v", requests.Load(), len(feedFindings(res)), feedDegradations(res))
	}

	dir, requests = feedProject(t, feedServers, 200, good, true)
	res, err = RunScanContext(context.Background(), dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 {
		t.Fatalf("--offline made %d feed requests", requests.Load())
	}
	ds := feedDegradations(res)
	if len(ds) != 1 || !ds[0].Advisory || !strings.Contains(ds[0].Detail, "offline") {
		t.Fatalf("offline with no cache = %+v", ds)
	}
	// Online once fills the cache; offline then reads it, still without a request.
	if _, err := RunScan(dir); err != nil {
		t.Fatal(err)
	}
	requests.Store(0)
	res, err = RunScanContext(context.Background(), dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 0 || len(feedFindings(res)) != 3 || len(feedDegradations(res)) != 0 {
		t.Fatalf("offline from the verified cache: requests=%d findings=%d degradations=%+v", requests.Load(), len(feedFindings(res)), feedDegradations(res))
	}
}

func TestMCPFeed_ReadsVSCodeServersToo(t *testing.T) {
	good, _ := os.ReadFile(mcpFeedTestdata + "feed.json")
	dir, _ := feedProject(t, `"x":{"command":"node","args":["s.js"]}`, 200, good, true)
	writeFile(t, filepath.Join(dir, ".vscode", "mcp.json"), `{"servers":{"evil":{"command":"npx","args":["evil-mcp-tool@3.0.0"]}}}`)
	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	fs := feedFindings(res)
	if len(fs) != 1 || fs[0].Severity != findings.SeverityHigh || fs[0].Location.FilePath != ".vscode/mcp.json" {
		t.Fatalf("findings = %+v", fs)
	}
	_ = degrade.MCP
}
