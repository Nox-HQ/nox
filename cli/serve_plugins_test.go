package main

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// installPluginsForTest points NOX_HOME at a fresh directory whose state lists
// the given plugins, as `nox plugin install` would have recorded them.
func installPluginsForTest(t *testing.T, plugins ...InstalledPlugin) {
	t.Helper()
	home := t.TempDir()
	t.Setenv("NOX_HOME", home)
	st := &State{Plugins: plugins}
	for i := range st.Plugins {
		st.Plugins[i].RecordBinaryDigest()
	}
	if err := SaveState(filepath.Join(home, "state.json"), st); err != nil {
		t.Fatalf("saving plugin state: %v", err)
	}
}

// `nox serve` never attached a plugin host, so the MCP server never offered
// plugin.list or plugin.call_tool: installed plugins were unreachable from an
// agent. Hosting plugins is opt-in (--plugins):
// an agent that can call a plugin tool runs a subprocess, and the operator
// should choose that. Without the flag nothing is started.
func TestServePluginHost(t *testing.T) {
	bin := buildPluginFixture(t, "authplugin")
	// netplugin declares proxy.golang.org, which core-analysis forbids: the
	// track's safety profile must hold through MCP as it does in a scan.
	netBin := buildPluginFixture(t, "netplugin")

	cases := []struct {
		name        string
		enabled     bool
		noxYAML     string // the workspace's .nox.yaml, if any
		wantPlugins []string
		notHosted   []string
		wantWarn    []string
	}{
		{name: "off by default", enabled: false},
		{
			name:        "hosts installed plugins under the scan's trust policy",
			enabled:     true,
			wantPlugins: []string{"nox/authtest"},
			notHosted:   []string{"nox/nettest"},
			// A plugin the host cannot run, or its policy refuses, is
			// reported and does not stop the others, as in a scan.
			wantWarn: []string{"nox/not-a-plugin", "proxy.golang.org"},
		},
		{
			// The workspace's .nox.yaml is the policy, as for a scan of it:
			// widening the allowlist admits the plugin through MCP too.
			name:        "the workspace policy widens what is hosted",
			enabled:     true,
			noxYAML:     "plugin_policy:\n  allowed_network_hosts: [\"proxy.golang.org\"]\n",
			wantPlugins: []string{"nox/authtest", "nox/nettest"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			installPluginsForTest(t,
				InstalledPlugin{Name: "nox/authtest", Version: "1.0.0", BinaryPath: bin, Track: "core-analysis"},
				InstalledPlugin{Name: "nox/not-a-plugin", Version: "1.0.0", BinaryPath: "/bin/echo", Track: "core-analysis"},
				InstalledPlugin{Name: "nox/nettest", Version: "1.0.0", BinaryPath: netBin, Track: "core-analysis"},
			)

			root := t.TempDir()
			if tc.noxYAML != "" {
				if err := os.WriteFile(filepath.Join(root, ".nox.yaml"), []byte(tc.noxYAML), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			host, warnings, err := servePluginHost(context.Background(), tc.enabled, root)
			if err != nil {
				t.Fatalf("servePluginHost: %v", err)
			}
			if !tc.enabled {
				if host != nil {
					_ = host.Close()
					t.Fatal("a plugin host was started without --plugins")
				}
				return
			}
			if host == nil {
				t.Fatal("--plugins started no plugin host")
			}
			defer func() { _ = host.Close() }()

			got := map[string]bool{}
			for _, info := range host.Plugins() {
				got[info.Name] = true
			}
			for _, name := range tc.wantPlugins {
				if !got[name] {
					t.Errorf("plugin %s is installed but not hosted; hosted: %v", name, got)
				}
			}
			for _, name := range tc.notHosted {
				if got[name] {
					t.Errorf("plugin %s is hosted although its track's policy refuses it", name)
				}
			}
			all := strings.Join(warnings, "\n")
			for _, w := range tc.wantWarn {
				if !strings.Contains(all, w) {
					t.Errorf("warnings do not mention %q: %q", w, warnings)
				}
			}
		})
	}
}
