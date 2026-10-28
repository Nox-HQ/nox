package core

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox-core/slopfeed"
	"github.com/nox-hq/nox/core/mcpfeed"
)

// The key as intel.klarlabs.de/v1/feeds/{slopsquat,mcp}.pub.pem serves it, and
// the SHA-256 of that file as served.
const (
	officialKeyBody       = "2ByJdNFjJEs1EDZB5C16bmRdMVdT62k3Ydv1GnqIYQs="
	officialKeyFilePinned = "381888c765e7bf41a642e7e0a92c9d3018a2e65ab08a9d5fb05cbb993ab4e23d"
)

// The built-in key bytes ARE the published key: this is the test that fails if
// the embedded file is edited, regenerated or replaced.
func TestBuiltinFeedKey_IsThePublishedKey(t *testing.T) {
	sum := sha256.Sum256(builtinFeedKeyPEM)
	if got := hex.EncodeToString(sum[:]); got != officialKeyFilePinned {
		t.Fatalf("embedded PEM sha256 = %s, the served file is %s", got, officialKeyFilePinned)
	}
	raw, _ := base64.StdEncoding.DecodeString(officialKeyBody)
	if len(raw) != ed25519.PublicKeySize {
		t.Fatalf("bad test constant")
	}
	rawSum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(rawSum[:])
	if got := BuiltinFeedKeyFingerprint(); got != want {
		t.Fatalf("fingerprint = %s, want %s", got, want)
	}
	k, err := builtinFeedKey()
	if err != nil || !k.builtin || k.source() != "built-in:slopfeed-key-v1" || BuiltinFeedKeyID != "slopfeed-key-v1" {
		t.Fatalf("builtinFeedKey = %+v, %v", k, err)
	}
}

func TestResolveFeedKey_ProjectKeyWinsAndIsNamed(t *testing.T) {
	pem, err := os.ReadFile(mcpFeedTestdata + "pub.pem")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "k.pem"), string(pem))
	k, err := resolveFeedKey(dir, "k.pem")
	if err != nil || k.builtin || !strings.HasPrefix(k.source(), "project:sha256:") || k.fingerprint == BuiltinFeedKeyFingerprint() {
		t.Fatalf("project key = %+v, %v", k, err)
	}
}

// useBuiltinKey makes the built-in key the test key for one test, so the
// built-in route can verify a feed the test signs. The real private key is not
// in this repository.
func useBuiltinKey(t *testing.T, pem []byte) {
	t.Helper()
	old := builtinFeedKeyPEM
	builtinFeedKeyPEM = pem
	t.Cleanup(func() { builtinFeedKeyPEM = old })
}

// serviceFixture is a fake NOX Intelligence service. It counts requests to the
// feed paths and serves servedKey at <feed>.pub.pem.
type serviceFixture struct {
	url      string
	requests atomic.Int32
}

func newService(t *testing.T, mcpBody, slopBody, servedKey []byte) *serviceFixture {
	t.Helper()
	s := &serviceFixture{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/v1/feeds/mcp", "/v1/feeds/slopsquat":
			s.requests.Add(1)
			body := mcpBody
			if strings.HasSuffix(r.URL.Path, "slopsquat") {
				body = slopBody
			}
			if body == nil {
				w.WriteHeader(http.StatusNotFound)
				_, _ = w.Write([]byte(`{"error":"not published"}`))
				return
			}
			_, _ = w.Write(body)
		case "/v1/feeds/mcp.pub.pem", "/v1/feeds/slopsquat.pub.pem":
			_, _ = w.Write(servedKey)
		default:
			_, _ = w.Write([]byte(`{"results":[]}`))
		}
	}))
	t.Cleanup(srv.Close)
	s.url = srv.URL
	return s
}

func feedConfigProject(t *testing.T, svc *serviceFixture, keyPath string) string {
	t.Helper()
	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, ".mcp.json"), `{"mcpServers":{`+feedServers+`}}`)
	writeFile(t, filepath.Join(dir, "requirements.txt"), "flask\n")
	writeFile(t, filepath.Join(dir, "app.py"), "import flask\nimport openai_utils\n")
	key := ""
	if keyPath != "" {
		key = "    signature_key_path: " + keyPath + "\n"
	}
	cfg := "scan:\n  intelligence:\n    endpoint: " + svc.url + "\n    verify_against_osv: false\n" +
		"  mcp_feed:\n    cache_dir: " + filepath.Join(dir, "cache-mcp") + "\n" + key +
		"  slop:\n    cache_dir: " + filepath.Join(dir, "cache-slop") + "\n" + key
	writeFile(t, filepath.Join(dir, ".nox.yaml"), cfg)
	return dir
}

func slopDegradations(res *ScanResult) []Degradation {
	var out []Degradation
	for _, d := range res.Degradations {
		if d.Kind == "slop_feed" {
			out = append(out, d)
		}
	}
	return out
}

func testSlopFeed(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	return signedFeedJSON(t, priv, slopfeed.Entry{
		Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious",
		Risk: 0.82, Tier: "critical", Reason: "unregistered", VerifiedAt: "2026-07-25",
	})
}

// freshKey generates a signing pair and returns the public half as PEM.
func freshKey(t *testing.T) (priv ed25519.PrivateKey, pubPEM []byte) {
	t.Helper()
	pub, priv, _ := ed25519.GenerateKey(nil)
	return priv, []byte(slopfeed.EncodePublicKeyPEM(pub))
}

// Default install, no signature_key_path: both feeds are consulted and verified
// under the built-in key, and the findings say so.
func TestFeeds_DefaultVerifyUnderBuiltinKey(t *testing.T) {
	priv, pub := freshKey(t)
	useBuiltinKey(t, pub)
	mcpBody := signMCPFeedForTest(t, priv)
	svc := newService(t, mcpBody, testSlopFeed(t, priv), pub)
	dir := feedConfigProject(t, svc, "")

	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if svc.requests.Load() != 2 {
		t.Fatalf("requests = %d, want one per feed", svc.requests.Load())
	}
	if n := len(feedFindings(res)); n != 3 {
		t.Fatalf("MCP-026 findings = %d", n)
	}
	for _, f := range feedFindings(res) {
		if f.Metadata["feed_key"] != "built-in:slopfeed-key-v1" {
			t.Errorf("MCP feed_key = %q", f.Metadata["feed_key"])
		}
	}
	slop2 := 0
	for _, f := range res.Findings.Findings() {
		if f.RuleID == "SLOP-002" {
			slop2++
			if f.Metadata["feed_key"] != "built-in:slopfeed-key-v1" {
				t.Errorf("SLOP-002 feed_key = %q", f.Metadata["feed_key"])
			}
		}
	}
	if slop2 != 1 || len(feedDegradations(res)) != 0 || len(slopDegradations(res)) != 0 {
		t.Fatalf("slop2=%d degradations mcp=%+v slop=%+v", slop2, feedDegradations(res), slopDegradations(res))
	}
}

// A configured key always wins over the built-in one: a feed signed by the
// project's key verifies even though the built-in key is someone else's.
func TestFeeds_ProjectKeyOverridesBuiltin(t *testing.T) {
	priv, pub := freshKey(t)
	_, otherPub := freshKey(t)
	useBuiltinKey(t, otherPub)
	svc := newService(t, signMCPFeedForTest(t, priv), testSlopFeed(t, priv), otherPub)
	dir := feedConfigProject(t, svc, "keys/mine.pem")
	writeFile(t, filepath.Join(dir, "keys", "mine.pem"), string(pub))

	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(feedFindings(res)) != 3 || len(feedDegradations(res)) != 0 || len(slopDegradations(res)) != 0 {
		t.Fatalf("mcp=%d degradations mcp=%+v slop=%+v", len(feedFindings(res)), feedDegradations(res), slopDegradations(res))
	}
	for _, f := range res.Findings.Findings() {
		if (f.RuleID == MCPFeedRuleID || f.RuleID == "SLOP-002") && !strings.HasPrefix(f.Metadata["feed_key"], "project:sha256:") {
			t.Errorf("%s feed_key = %q, want the project key", f.RuleID, f.Metadata["feed_key"])
		}
	}
	if countRule(res, "SLOP-002") != 1 {
		t.Fatal("SLOP-002 did not fire under the project key")
	}
}

// A feed that does not verify under the built-in key is never used and blocks.
func TestFeeds_TamperedUnderBuiltinKeyBlocks(t *testing.T) {
	priv, pub := freshKey(t)
	useBuiltinKey(t, pub)
	mcpBody := []byte(strings.Replace(string(signMCPFeedForTest(t, priv)), "Directory escape", "Nothing to see", 1))
	slopBody := []byte(strings.Replace(string(testSlopFeed(t, priv)), "openai-utils", "openai-utilz", 1))
	svc := newService(t, mcpBody, slopBody, pub)
	res, err := RunScan(feedConfigProject(t, svc, ""))
	if err != nil {
		t.Fatal(err)
	}
	if len(feedFindings(res)) != 0 || countRule(res, "SLOP-002") != 0 {
		t.Fatal("a tampered feed was used")
	}
	m, s := feedDegradations(res), slopDegradations(res)
	if len(m) != 1 || m[0].Advisory || len(s) != 1 || s[0].Advisory {
		t.Fatalf("tampered feeds must be blocking degradations: mcp=%+v slop=%+v", m, s)
	}
}

// Signed by a key that is not the built-in one while the service still serves
// the built-in key: blocking, and says which key it was verified against.
func TestFeeds_WrongSignerBlocksAndNamesBuiltinKey(t *testing.T) {
	_, builtinPub := freshKey(t)
	useBuiltinKey(t, builtinPub)
	attacker, _ := freshKey(t)
	svc := newService(t, signMCPFeedForTest(t, attacker), testSlopFeed(t, attacker), builtinPub)
	res, err := RunScan(feedConfigProject(t, svc, ""))
	if err != nil {
		t.Fatal(err)
	}
	for _, ds := range [][]Degradation{feedDegradations(res), slopDegradations(res)} {
		if len(ds) != 1 || ds[0].Advisory || !strings.Contains(ds[0].Detail, "built-in key slopfeed-key-v1") || strings.Contains(ds[0].Detail, "rotated") {
			t.Fatalf("degradation = %+v", ds)
		}
	}
	if len(feedFindings(res)) != 0 || countRule(res, "SLOP-002") != 0 {
		t.Fatal("a feed signed by the wrong key was used")
	}
}

// The service signs with a different key than the one built in: nox does not
// accept it, names both fingerprints and tells the user what to do.
func TestFeeds_RotatedServedKeyIsReportedNotAccepted(t *testing.T) {
	_, builtinPub := freshKey(t)
	useBuiltinKey(t, builtinPub)
	newPriv, newPub := freshKey(t)
	svc := newService(t, signMCPFeedForTest(t, newPriv), testSlopFeed(t, newPriv), newPub)
	res, err := RunScan(feedConfigProject(t, svc, ""))
	if err != nil {
		t.Fatal(err)
	}
	newFP, _ := feedKeyFingerprint(newPub)
	oldFP := BuiltinFeedKeyFingerprint()
	for _, ds := range [][]Degradation{feedDegradations(res), slopDegradations(res)} {
		if len(ds) != 1 || ds[0].Advisory {
			t.Fatalf("degradation = %+v", ds)
		}
		d := ds[0].Detail
		for _, want := range []string{newFP, oldFP, "rotated", "upgrade nox", "signature_key_path"} {
			if !strings.Contains(d, want) {
				t.Errorf("detail missing %q: %s", want, d)
			}
		}
	}
	if len(feedFindings(res)) != 0 || countRule(res, "SLOP-002") != 0 {
		t.Fatal("a feed signed by a rotated key was trusted")
	}
}

// Offline and intelligence-disabled scans make no request, and say why.
func TestFeeds_OfflineAndIntelligenceDisabledMakeNoRequest(t *testing.T) {
	priv, pub := freshKey(t)
	useBuiltinKey(t, pub)
	svc := newService(t, signMCPFeedForTest(t, priv), testSlopFeed(t, priv), pub)

	dir := feedConfigProject(t, svc, "")
	res, err := RunScanContext(context.Background(), dir, ScanOptions{Offline: true})
	if err != nil {
		t.Fatal(err)
	}
	if svc.requests.Load() != 0 {
		t.Fatalf("--offline made %d feed requests", svc.requests.Load())
	}
	m, s := feedDegradations(res), slopDegradations(res)
	if len(m) != 1 || !m[0].Advisory || !strings.Contains(m[0].Detail, "offline") ||
		len(s) != 1 || !s[0].Advisory || !strings.Contains(s[0].Detail, "offline") || !strings.Contains(s[0].Detail, "not checked") {
		t.Fatalf("offline: mcp=%+v slop=%+v", m, s)
	}

	dir = feedConfigProject(t, svc, "")
	writeFile(t, filepath.Join(dir, ".nox.yaml"), "scan:\n  intelligence:\n    disabled: true\n")
	res, err = RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if svc.requests.Load() != 0 {
		t.Fatalf("intelligence disabled made %d feed requests", svc.requests.Load())
	}
	m, s = feedDegradations(res), slopDegradations(res)
	if len(m) != 1 || !strings.Contains(m[0].Detail, "scan.intelligence.disabled") || len(s) != 1 || !strings.Contains(s[0].Detail, "scan.intelligence.disabled") {
		t.Fatalf("disabled: mcp=%+v slop=%+v", m, s)
	}
}

// Each feed has its own explicit opt-out.
func TestFeeds_PerFeedOptOut(t *testing.T) {
	priv, pub := freshKey(t)
	useBuiltinKey(t, pub)
	svc := newService(t, signMCPFeedForTest(t, priv), testSlopFeed(t, priv), pub)
	dir := feedConfigProject(t, svc, "")
	cfg := mustRead(t, filepath.Join(dir, ".nox.yaml"))
	cfg = strings.Replace(cfg, "  slop:\n", "  slop:\n    disabled: true\n", 1)
	writeFile(t, filepath.Join(dir, ".nox.yaml"), cfg)
	res, err := RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if svc.requests.Load() != 1 || countRule(res, "SLOP-002") != 0 || len(slopDegradations(res)) != 0 || len(feedFindings(res)) != 3 {
		t.Fatalf("slop opt-out: requests=%d slop2=%d", svc.requests.Load(), countRule(res, "SLOP-002"))
	}

	svc2 := newService(t, signMCPFeedForTest(t, priv), testSlopFeed(t, priv), pub)
	dir = feedConfigProject(t, svc2, "")
	cfg = mustRead(t, filepath.Join(dir, ".nox.yaml"))
	cfg = strings.Replace(cfg, "  mcp_feed:\n", "  mcp_feed:\n    disabled: true\n", 1)
	writeFile(t, filepath.Join(dir, ".nox.yaml"), cfg)
	res, err = RunScan(dir)
	if err != nil {
		t.Fatal(err)
	}
	if svc2.requests.Load() != 1 || len(feedFindings(res)) != 0 || len(feedDegradations(res)) != 0 || countRule(res, "SLOP-002") != 1 {
		t.Fatalf("mcp opt-out: requests=%d", svc2.requests.Load())
	}
}

// A service that has not published a slopsquat feed is not the operator's to fix.
func TestFeeds_SlopNotPublishedIsAdvisory(t *testing.T) {
	priv, pub := freshKey(t)
	useBuiltinKey(t, pub)
	svc := newService(t, signMCPFeedForTest(t, priv), nil, pub)
	res, err := RunScan(feedConfigProject(t, svc, ""))
	if err != nil {
		t.Fatal(err)
	}
	s := slopDegradations(res)
	if len(s) != 1 || !s[0].Advisory || !strings.Contains(s[0].Detail, "has not published") {
		t.Fatalf("slop = %+v", s)
	}
}

func mustRead(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// signMCPFeedForTest re-signs the checked-in MCP test feed under priv, the way
// the service does: digest over the canonical entries, Ed25519 over the
// domain-prefixed canonical bytes.
func signMCPFeedForTest(t *testing.T, priv ed25519.PrivateKey) []byte {
	t.Helper()
	var f mcpfeed.Feed
	if err := json.Unmarshal([]byte(mustRead(t, mcpFeedTestdata+"feed.json")), &f); err != nil {
		t.Fatal(err)
	}
	content, err := mcpfeed.Canonical(f.Entries)
	if err != nil {
		t.Fatal(err)
	}
	f.Digest = mcpfeed.Digest(content)
	f.Signature = &mcpfeed.Signature{Algorithm: "ed25519", KeyID: "test", Value: base64.StdEncoding.EncodeToString(ed25519.Sign(priv, append([]byte(mcpfeed.SignedContext), content...)))}
	out, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// The default feed must be signed: a service answer with a valid digest and no
// signature is not a feed, because a digest alone proves nothing about who made it.
func TestFeeds_DefaultSlopFeedRequiresASignature(t *testing.T) {
	priv, pub := freshKey(t)
	useBuiltinKey(t, pub)
	f := &slopfeed.Feed{SchemaVersion: slopfeed.SchemaVersion, Version: "u", GeneratedAt: "2026-07-25T00:00:00Z", Source: "test",
		Entries: []slopfeed.Entry{{Name: "openai-utils", Ecosystem: "pypi", Pattern: "obvious", Risk: 0.82, Tier: "critical", Reason: "r", VerifiedAt: "2026-07-25"}}}
	if err := f.SetDigest(); err != nil {
		t.Fatal(err)
	}
	unsigned, _ := json.Marshal(f)
	svc := newService(t, signMCPFeedForTest(t, priv), unsigned, pub)
	res, err := RunScan(feedConfigProject(t, svc, ""))
	if err != nil {
		t.Fatal(err)
	}
	s := slopDegradations(res)
	if countRule(res, "SLOP-002") != 0 || len(s) != 1 || s[0].Advisory {
		t.Fatalf("an unsigned default feed was used or not blocking: %+v", s)
	}
}
