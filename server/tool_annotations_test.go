package server

import (
	"testing"

	"github.com/nox-hq/nox/plugin"
	mcp "go.klarlabs.de/mcp"
)

// Every tool must say what it does. A tool with no annotations is read by a
// client as destructive and open-world, which is wrong for a read-only tool and
// unspecific for a mutating one; the two mutating tool families were the ones
// that carried none.
func TestEveryToolDeclaresItsEffects(t *testing.T) {
	s := New("0.1.0", nil, WithPluginHost(plugin.NewHost()))
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	s.registerTools(srv)

	type want struct{ readOnly, destructive, idempotent, openWorld *bool }
	tru, fls := hint(true), hint(false)
	mutating := map[string]want{
		"baseline_add":      {fls, fls, tru, fls},
		"baseline_add_many": {fls, fls, tru, fls},
		"plugin_install":    {fls, tru, tru, tru},
	}
	// Tools that reach out of the machine.
	openWorld := map[string]bool{"scan": true, "diff": true, "plugin.call_tool": true}

	tools := srv.Tools()
	if len(tools) < 25 {
		t.Fatalf("only %d tools registered; the audit would be vacuous", len(tools))
	}
	for _, tool := range tools {
		a := tool.Annotations
		if a == nil {
			t.Errorf("tool %q has no annotations", tool.Name)
			continue
		}
		if a.ReadOnlyHint == nil || a.OpenWorldHint == nil {
			t.Errorf("tool %q leaves readOnlyHint or openWorldHint unset: %+v", tool.Name, a)
			continue
		}
		if w, ok := mutating[tool.Name]; ok {
			if *a.ReadOnlyHint != *w.readOnly || a.DestructiveHint == nil || *a.DestructiveHint != *w.destructive ||
				a.IdempotentHint == nil || *a.IdempotentHint != *w.idempotent || *a.OpenWorldHint != *w.openWorld {
				t.Errorf("tool %q annotations = %+v, want readOnly=%v destructive=%v idempotent=%v openWorld=%v",
					tool.Name, a, *w.readOnly, *w.destructive, *w.idempotent, *w.openWorld)
			}
			continue
		}
		if !*a.ReadOnlyHint {
			t.Errorf("tool %q is not read-only and is not in the mutating table: add it with its reasons", tool.Name)
		}
		if *a.OpenWorldHint != openWorld[tool.Name] {
			t.Errorf("tool %q openWorldHint = %v, want %v", tool.Name, *a.OpenWorldHint, openWorld[tool.Name])
		}
	}
	for name := range mutating {
		found := false
		for _, tool := range tools {
			found = found || tool.Name == name
		}
		if !found {
			t.Errorf("mutating table names %q, which is not a registered tool", name)
		}
	}
}
