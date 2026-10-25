// Package testenv makes a package's tests hermetic. Call Main from TestMain.
//
// A scan with default config consults NOX Intelligence and its signed feeds and
// caches under $HOME/.nox, so a test that scans without saying otherwise would
// reach the real service and read the developer's real cache. Main closes that
// at the root rather than per test:
//
//   - HOME and USERPROFILE point at a fresh temp directory, so no test reads or
//     writes the real ~/.nox;
//   - NOX_INTEL_ENDPOINT and NOX_OSV_BASE_URL name a closed loopback port, so the default endpoint
//     is unreachable (a test that configures its own httptest endpoint still
//     wins: config beats the environment);
//   - http.DefaultTransport's dialer refuses any non-loopback host, and the run FAILS if
//     anything tried, so a regression cannot pass by merely being offline.
package testenv

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"os"
	"sync"
	"testing"
)

// ClosedEndpoint is an unroutable local address nothing listens on.
const ClosedEndpoint = "http://127.0.0.1:1"

type guard struct {
	mu   sync.Mutex
	seen map[string]struct{}
}

// dial refuses any non-loopback address. It guards the dialer rather than
// replacing http.DefaultTransport, because callers assert that the default
// transport is an *http.Transport. Proxies are ignored for the same reason the
// dialer is checked: a request is judged by where it was addressed.
func (g *guard) dial(next func(context.Context, string, string) (net.Conn, error)) func(context.Context, string, string) (net.Conn, error) {
	return func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, _, err := net.SplitHostPort(addr)
		if err != nil {
			host = addr
		}
		if ip := net.ParseIP(host); host == "localhost" || (ip != nil && ip.IsLoopback()) {
			return next(ctx, network, addr)
		}
		g.mu.Lock()
		g.seen[addr] = struct{}{}
		g.mu.Unlock()
		return nil, fmt.Errorf("testenv: test tried to reach non-loopback host %s", addr)
	}
}

// Main runs the package's tests hermetically and returns the exit code.
func Main(m *testing.M) int {
	home, err := os.MkdirTemp("", "nox-test-home-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "testenv:", err)
		return 1
	}
	defer func() { _ = os.RemoveAll(home) }()
	for k, v := range map[string]string{"HOME": home, "USERPROFILE": home, "NOX_INTEL_ENDPOINT": ClosedEndpoint, "NOX_OSV_BASE_URL": ClosedEndpoint} {
		_ = os.Setenv(k, v)
	}
	g := &guard{seen: map[string]struct{}{}}
	if t, ok := http.DefaultTransport.(*http.Transport); ok {
		t.Proxy = nil
		t.DialContext = g.dial((&net.Dialer{}).DialContext)
	}

	code := m.Run()
	if len(g.seen) > 0 && code == 0 {
		fmt.Fprintf(os.Stderr, "testenv: tests reached non-loopback hosts: %v\n", g.seen)
		return 1
	}
	return code
}
