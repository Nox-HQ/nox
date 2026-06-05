package discovery

import (
	"strings"
	"testing"
)

func TestKnownClientConfigs_PerOS(t *testing.T) {
	cases := []struct {
		goos    string
		env     ClientEnv
		client  string
		wantSub string // substring the resolved path must contain
	}{
		{
			goos:    "darwin",
			env:     ClientEnv{Home: "/Users/alice", GOOS: "darwin"},
			client:  "Claude Desktop",
			wantSub: "/Users/alice/Library/Application Support/Claude/claude_desktop_config.json",
		},
		{
			goos:    "linux",
			env:     ClientEnv{Home: "/home/alice", GOOS: "linux"},
			client:  "Claude Desktop",
			wantSub: "/home/alice/.config/Claude/claude_desktop_config.json",
		},
		{
			goos:    "windows",
			env:     ClientEnv{Home: `C:\Users\alice`, AppData: `C:\Users\alice\AppData\Roaming`, GOOS: "windows"},
			client:  "Claude Desktop",
			wantSub: `C:\Users\alice\AppData\Roaming\Claude\claude_desktop_config.json`,
		},
		{
			goos:    "darwin",
			env:     ClientEnv{Home: "/Users/alice", GOOS: "darwin"},
			client:  "Cursor",
			wantSub: "/Users/alice/.cursor/mcp.json",
		},
	}

	for _, tc := range cases {
		t.Run(tc.goos+"/"+tc.client, func(t *testing.T) {
			configs := KnownClientConfigs(tc.env)
			var got string
			for _, c := range configs {
				if c.Client == tc.client {
					got = c.Path
					break
				}
			}
			if got == "" {
				t.Fatalf("client %q not found for %s", tc.client, tc.goos)
			}
			if got != tc.wantSub {
				t.Errorf("path = %q, want %q", got, tc.wantSub)
			}
		})
	}
}

func TestKnownClientConfigs_Coverage(t *testing.T) {
	configs := KnownClientConfigs(ClientEnv{Home: "/home/u", GOOS: "linux"})
	if len(configs) < 15 {
		t.Errorf("expected at least 15 client configs on linux, got %d", len(configs))
	}
	// Deterministic ordering.
	for i := 1; i < len(configs); i++ {
		if configs[i-1].Client > configs[i].Client {
			t.Errorf("client configs not sorted: %q before %q", configs[i-1].Client, configs[i].Client)
		}
	}
	// No empty paths.
	for _, c := range configs {
		if c.Path == "" || !strings.Contains(c.Path, "/home/u") {
			t.Errorf("client %q has unexpected path %q", c.Client, c.Path)
		}
	}
}

func TestResolveExisting_FiltersByExistence(t *testing.T) {
	env := ClientEnv{Home: "/home/u", GOOS: "linux"}
	want := KnownClientConfigs(env)[0].Path
	got := resolveExisting(env, func(p string) bool { return p == want })
	if len(got) != 1 || got[0].Path != want {
		t.Fatalf("expected only %q, got %+v", want, got)
	}
}

func TestClassify_MCPClientConfigNames(t *testing.T) {
	cases := []struct {
		path string
		want bool
	}{
		{"mcp.json", true},
		{".cursor/mcp.json", true},
		{"claude_desktop_config.json", true},
		{"cline_mcp_settings.json", true},
		{"server.mcp.json", true},
		{"config.json", false},
		{"package.json", false},
	}
	for _, tc := range cases {
		name := tc.path
		if i := strings.LastIndex(tc.path, "/"); i >= 0 {
			name = tc.path[i+1:]
		}
		if got := isAIComponent(name, tc.path); got != tc.want {
			t.Errorf("isAIComponent(%q) = %v, want %v", tc.path, got, tc.want)
		}
	}
}
