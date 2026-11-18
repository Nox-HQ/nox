package npmtree

import "testing"

// An npm workspace lists each member under its own directory, with no
// node_modules segment: argotorg/sourcify records "ui" (named sourcify-ui) and
// "packages/lib-sourcify" (named @ethereum-sourcify/lib-sourcify). npmGraph
// cut the name after the last "node_modules/", so a member key shorter than
// that marker panicked (slice bounds out of range [12:2]) and aborted the
// whole scan, and a longer one became a nonsense name ("-sourcify").
func TestNpmGraphReadsWorkspaceMembers(t *testing.T) {
	pkgs := map[string]lockEntry{
		"": {Dependencies: map[string]string{"sourcify-ui": "*"}},
		"ui": {
			Name: "sourcify-ui", Version: "1.1.0",
			Dependencies: map[string]string{"axios": "^1.6.0"},
		},
		"packages/lib-sourcify": {
			Name: "@ethereum-sourcify/lib-sourcify", Version: "1.3.0",
		},
		"services/no-name":        {Version: "0.1.0"},
		"node_modules/axios":      {Version: "1.6.2"},
		"ui/node_modules/axios":   {Version: "1.7.0"},
		"node_modules/@scope/pkg": {Version: "2.0.0"},
	}
	g := npmGraph(pkgs)
	want := map[string]string{
		"ui":                      "sourcify-ui",
		"packages/lib-sourcify":   "@ethereum-sourcify/lib-sourcify",
		"services/no-name":        "no-name",
		"node_modules/axios":      "axios",
		"ui/node_modules/axios":   "axios",
		"node_modules/@scope/pkg": "@scope/pkg",
	}
	for key, name := range want {
		if got := g.nodes[key].name; got != name {
			t.Errorf("node %q named %q, want %q", key, got, name)
		}
	}
	// A request from the workspace member resolves through its own
	// node_modules first, then the root's.
	if got := g.resolve("ui", "axios", "^1.6.0"); got != "ui/node_modules/axios" {
		t.Errorf("ui -> axios resolved to %q, want ui/node_modules/axios", got)
	}
	if got := g.resolve("packages/lib-sourcify", "axios", "*"); got != "node_modules/axios" {
		t.Errorf("lib-sourcify -> axios resolved to %q, want node_modules/axios", got)
	}
}
