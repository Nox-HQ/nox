package server

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	pluginv1 "github.com/nox-hq/nox/gen/nox/plugin/v1"
	"github.com/nox-hq/nox/plugin"
)

// plugin.call_tool checked workspace_root against the allowed roots only when
// the caller supplied one, and never looked at input.workspace_root, which is
// where plugins read their root from (the scan path sets both). An agent could
// therefore aim a plugin anywhere: omit workspace_root, or put "/etc" inside
// input. Unreachable while `nox serve` hosted no plugins; `--plugins` makes it
// reachable, so the server now gives every call a confined root in both
// places.
func TestPluginCallToolConfinesTheWorkspace(t *testing.T) {
	allowed := t.TempDir()
	inside := filepath.Join(allowed, "sub")
	outside := t.TempDir()

	cases := []struct {
		name      string
		input     pluginCallToolInput
		wantError string // empty: the call reaches the plugin
		wantRoot  string // the root the plugin sees, in both places
	}{
		{
			name:     "no root given: the first allowed root",
			input:    pluginCallToolInput{Tool: "test-scanner.scan"},
			wantRoot: allowed,
		},
		{
			name:     "a root under an allowed one is passed in both places",
			input:    pluginCallToolInput{Tool: "test-scanner.scan", WorkspaceRoot: inside},
			wantRoot: inside,
		},
		{
			name:      "a root outside is refused",
			input:     pluginCallToolInput{Tool: "test-scanner.scan", WorkspaceRoot: outside},
			wantError: "outside allowed workspaces",
		},
		{
			name: "input.workspace_root outside is refused",
			input: pluginCallToolInput{
				Tool:  "test-scanner.scan",
				Input: map[string]any{"workspace_root": outside},
			},
			wantError: "outside allowed workspaces",
		},
		{
			name: "input.workspace_root must agree with workspace_root",
			input: pluginCallToolInput{
				Tool:          "test-scanner.scan",
				WorkspaceRoot: allowed,
				Input:         map[string]any{"workspace_root": inside},
			},
			wantError: "workspace_root",
		},
		{
			name: "input.workspace_root that is not a string is refused",
			input: pluginCallToolInput{
				Tool:  "test-scanner.scan",
				Input: map[string]any{"workspace_root": 7.0},
			},
			wantError: "workspace_root",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var mu sync.Mutex
			var seenRoot, seenInputRoot string
			called := false
			mock := &testMockPluginServer{
				manifest: testValidManifest(),
				invokeFunc: func(_ context.Context, req *pluginv1.InvokeToolRequest) (*pluginv1.InvokeToolResponse, error) {
					mu.Lock()
					defer mu.Unlock()
					called = true
					seenRoot = req.GetWorkspaceRoot()
					if v, ok := req.GetInput().AsMap()["workspace_root"].(string); ok {
						seenInputRoot = v
					}
					return &pluginv1.InvokeToolResponse{}, nil
				},
			}
			h := plugin.NewHost()
			if err := h.RegisterPlugin(context.Background(), startTestMockPlugin(t, mock)); err != nil {
				t.Fatalf("registering mock plugin: %v", err)
			}
			s := New("0.1.0", []string{allowed}, WithPluginHost(h))

			result, err := s.handlePluginCallTool(context.Background(), tc.input)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			mu.Lock()
			defer mu.Unlock()
			if tc.wantError != "" {
				if !strings.HasPrefix(result, "Error:") || !strings.Contains(result, tc.wantError) {
					t.Fatalf("want an error mentioning %q, got: %s", tc.wantError, result)
				}
				if called {
					t.Fatal("the plugin was invoked although the call was refused")
				}
				return
			}
			if strings.HasPrefix(result, "Error:") {
				t.Fatalf("unexpected refusal: %s", result)
			}
			if !samePath(seenRoot, tc.wantRoot) || !samePath(seenInputRoot, tc.wantRoot) {
				t.Errorf("plugin saw workspace_root %q and input.workspace_root %q, want %q in both",
					seenRoot, seenInputRoot, tc.wantRoot)
			}
		})
	}
}

// samePath compares paths after symlink resolution (/var is /private/var on
// macOS, and t.TempDir lives under it).
func samePath(a, b string) bool {
	ra, errA := filepath.EvalSymlinks(a)
	rb, errB := filepath.EvalSymlinks(b)
	if errA != nil || errB != nil {
		return filepath.Clean(a) == filepath.Clean(b)
	}
	return ra == rb
}
