package deps

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// tripwireTransport fails the test if any HTTP request is attempted and records
// that an egress was made.
type tripwireTransport struct{ called bool }

func (t *tripwireTransport) RoundTrip(*http.Request) (*http.Response, error) {
	t.called = true
	return nil, fmt.Errorf("network egress attempted")
}

func lockfileArtifact(t *testing.T) []discovery.Artifact {
	t.Helper()
	tmp := t.TempDir()
	content := []byte(`{"packages":{"node_modules/express":{"version":"4.18.2"}}}`)
	p := filepath.Join(tmp, "package-lock.json")
	if err := os.WriteFile(p, content, 0o644); err != nil {
		t.Fatalf("write lockfile: %v", err)
	}
	return []discovery.Artifact{{
		Path: "package-lock.json", AbsPath: p, Type: discovery.Lockfile, Size: int64(len(content)),
	}}
}

// Zero-telemetry guarantee: with OSV disabled, scanning a lockfile makes no
// outbound network call. OSV is the only network path in the core scan, so a
// tripwire on the deps HTTP client proves the offline guarantee end to end.
func TestOSVDisabled_NoNetworkEgress(t *testing.T) {
	tw := &tripwireTransport{}
	a := NewAnalyzer(WithOSVDisabled(), WithHTTPClient(&http.Client{Transport: tw}))

	if _, _, err := a.ScanArtifacts(context.Background(), lockfileArtifact(t)); err != nil {
		t.Fatalf("offline scan returned error: %v", err)
	}
	if tw.called {
		t.Fatal("OSV-disabled scan attempted a network connection")
	}
}

// Positive control: with OSV enabled (the default), the same lockfile DOES
// trigger an egress attempt. This proves the tripwire actually detects network
// use and that OSV is the egress path the offline guarantee gates. OSV degrades
// gracefully on network failure, so no error surfaces — we assert on the
// attempt itself.
func TestOSVEnabled_AttemptsEgress(t *testing.T) {
	tw := &tripwireTransport{}
	a := NewAnalyzer(WithHTTPClient(&http.Client{Transport: tw}))

	if _, _, err := a.ScanArtifacts(context.Background(), lockfileArtifact(t)); err != nil {
		t.Fatalf("scan returned error: %v", err)
	}
	if !tw.called {
		t.Fatal("OSV-enabled scan should have attempted a network connection")
	}
}
