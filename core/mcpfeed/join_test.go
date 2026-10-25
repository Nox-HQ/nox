package mcpfeed

import (
	"testing"

	"github.com/nox-hq/nox/core/mcpconfig"
)

func loadServiceFeed(t *testing.T) *Feed {
	t.Helper()
	body, verify := serviceFeed(t)
	f, err := Parse(body, verify)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func srv(name, eco, pkg, version string) Server {
	return Server{Config: ".mcp.json", Line: 3, Name: name, Package: mcpconfig.PackageRef{Ecosystem: eco, Name: pkg, Version: version, Pinned: version != ""}}
}

func ids(es []Entry) []string {
	var out []string
	for _, e := range es {
		out = append(out, e.AdvisoryID)
	}
	return out
}

func TestCheckMatchesPinnedVersionsAgainstTheEntrysOwnRanges(t *testing.T) {
	f := loadServiceFeed(t)
	cases := []struct {
		name    string
		server  Server
		mode    Mode
		wantIDs []string // nil: no hit
	}{
		{"inside the first interval", srv("a", "npm", "mcp-server-x", "1.4.1"), ModeRange, []string{"GHSA-zzzz-0002"}},
		{"on the fixed version: not affected", srv("a", "npm", "mcp-server-x", "1.4.2"), "", nil},
		{"between the intervals", srv("a", "npm", "mcp-server-x", "1.9.0"), "", nil},
		{"inside the second interval", srv("a", "npm", "mcp-server-x", "2.0.5"), ModeRange, []string{"GHSA-zzzz-0002"}},
		{"after every interval", srv("a", "npm", "mcp-server-x", "2.1.0"), "", nil},
		{"scoped package, calendar version", srv("fs", "npm", "@modelcontextprotocol/server-filesystem", "2025.1.14"), ModeRange, []string{"GHSA-aaaa-0001"}},
		{"scoped package, fixed", srv("fs", "npm", "@modelcontextprotocol/server-filesystem", "2025.7.1"), "", nil},
		{"last_affected is inclusive", srv("g", "PyPI", "mcp-server-git", "0.6.2"), ModeRange, []string{"GHSA-pppp-0003"}},
		{"after last_affected", srv("g", "PyPI", "mcp-server-git", "0.6.3"), "", nil},
		{"PyPI names compare under PEP 503", srv("g", "PyPI", "MCP_Server.Git", "0.1.0"), ModeRange, []string{"GHSA-pppp-0003"}},
		{"introduced 0 with no upper bound", srv("e", "npm", "evil-mcp-tool", "9.9.9"), ModeRange, []string{"MAL-2026-1"}},
		{"another ecosystem's package of the same name", srv("x", "PyPI", "mcp-server-x", "1.0.0"), "", nil},
		{"a package the feed does not list", srv("z", "npm", "left-pad", "1.0.0"), "", nil},
		{"a candidate's free-text range is not evaluated", srv("c", "npm", "candidate-mcp-server", "1.1.0"), ModeUnevaluated, []string{"NOX-CAND-0007"}},
		{"a version that cannot be ordered is never affected", srv("x", "npm", "mcp-server-x", "latest-ish"), ModeUnevaluated, []string{"GHSA-zzzz-0002"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			hits := f.Check([]Server{c.server})
			if c.wantIDs == nil {
				if len(hits) != 0 {
					t.Fatalf("expected no hit, got %+v", hits)
				}
				return
			}
			if len(hits) != 1 || hits[0].Mode != c.mode || len(ids(hits[0].Entries)) != len(c.wantIDs) || ids(hits[0].Entries)[0] != c.wantIDs[0] {
				t.Fatalf("hits = %+v, want mode %s ids %v", hits, c.mode, c.wantIDs)
			}
		})
	}
}

// Without a pinned version no interval can be tested: say that advisories
// exist, never that the server is affected.
func TestCheckReportsUnpinnedServersAsUnpinned(t *testing.T) {
	f := loadServiceFeed(t)
	hits := f.Check([]Server{srv("a", "npm", "mcp-server-x", ""), srv("n", "npm", "not-listed", "")})
	if len(hits) != 1 || hits[0].Mode != ModeUnpinned || hits[0].Server.Name != "a" || len(hits[0].Entries) != 1 {
		t.Fatalf("hits = %+v", hits)
	}
}

func TestCheckIsDeterministic(t *testing.T) {
	f := loadServiceFeed(t)
	in := []Server{srv("b", "npm", "mcp-server-x", "1.0.0"), srv("a", "npm", "evil-mcp-tool", "1.0.0")}
	first := f.Check(in)
	for i := 0; i < 5; i++ {
		again := f.Check([]Server{in[1], in[0]})
		if len(again) != len(first) || again[0].Server.Name != first[0].Server.Name {
			t.Fatalf("order depends on input order: %+v vs %+v", first, again)
		}
	}
	if first[0].Server.Name != "a" {
		t.Errorf("hits are ordered by config then server name: %+v", first)
	}
}
