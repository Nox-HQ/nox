package discovery

import (
	"os"
	"runtime"
	"sort"
	"strings"
)

// ClientEnv carries the environment inputs needed to resolve MCP client config
// locations. Pulled into a struct so resolution is a pure function that can be
// exercised with per-OS fixtures in tests.
type ClientEnv struct {
	Home    string // user home directory
	AppData string // Windows %APPDATA% (ignored on other platforms)
	GOOS    string // "darwin", "linux", "windows"
}

// CurrentClientEnv returns the ClientEnv for the running process.
func CurrentClientEnv() ClientEnv {
	home, _ := os.UserHomeDir()
	return ClientEnv{
		Home:    home,
		AppData: os.Getenv("APPDATA"),
		GOOS:    runtime.GOOS,
	}
}

// mcpConfigNames is the set of bare filenames that identify an MCP client
// configuration file when encountered during an in-tree walk. *.mcp.json is
// handled separately by suffix.
var mcpConfigNames = map[string]bool{
	"mcp.json":                   true,
	"claude_desktop_config.json": true,
	"cline_mcp_settings.json":    true,
	"mcp_config.json":            true,
}

// MCPClientConfig is a known MCP client configuration location.
type MCPClientConfig struct {
	Client string // human-readable client name, e.g. "Claude Desktop"
	Path   string // absolute path to the config file for the current OS
}

// configSpec describes where a client stores its MCP config, per OS, as path
// segments joined under the relevant base directory.
type configSpec struct {
	client    string
	darwin    []string // relative to $HOME
	linux     []string // relative to $HOME
	windows   []string // relative to %APPDATA% (falls back to $HOME)
	winFromHo bool     // when true, windows path is relative to $HOME not %APPDATA%
}

// clientSpecs enumerates the well-known MCP client config locations. These are
// the user-level (global) configs; project-level configs (e.g. .cursor/mcp.json,
// .vscode/mcp.json, .mcp.json) are picked up by the normal in-tree walk via
// isAIComponent.
var clientSpecs = []configSpec{
	{
		client:  "Claude Desktop",
		darwin:  []string{"Library", "Application Support", "Claude", "claude_desktop_config.json"},
		linux:   []string{".config", "Claude", "claude_desktop_config.json"},
		windows: []string{"Claude", "claude_desktop_config.json"},
	},
	{
		client:    "Claude Code",
		darwin:    []string{".claude.json"},
		linux:     []string{".claude.json"},
		windows:   []string{".claude.json"},
		winFromHo: true,
	},
	{
		client:    "Cursor",
		darwin:    []string{".cursor", "mcp.json"},
		linux:     []string{".cursor", "mcp.json"},
		windows:   []string{".cursor", "mcp.json"},
		winFromHo: true,
	},
	{
		client:  "VS Code",
		darwin:  []string{"Library", "Application Support", "Code", "User", "mcp.json"},
		linux:   []string{".config", "Code", "User", "mcp.json"},
		windows: []string{"Code", "User", "mcp.json"},
	},
	{
		client:  "VS Code Insiders",
		darwin:  []string{"Library", "Application Support", "Code - Insiders", "User", "mcp.json"},
		linux:   []string{".config", "Code - Insiders", "User", "mcp.json"},
		windows: []string{"Code - Insiders", "User", "mcp.json"},
	},
	{
		client:    "Windsurf",
		darwin:    []string{".codeium", "windsurf", "mcp_config.json"},
		linux:     []string{".codeium", "windsurf", "mcp_config.json"},
		windows:   []string{".codeium", "windsurf", "mcp_config.json"},
		winFromHo: true,
	},
	{
		client:  "Cline",
		darwin:  []string{"Library", "Application Support", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"},
		linux:   []string{".config", "Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"},
		windows: []string{"Code", "User", "globalStorage", "saoudrizwan.claude-dev", "settings", "cline_mcp_settings.json"},
	},
	{
		client:    "Continue",
		darwin:    []string{".continue", "config.json"},
		linux:     []string{".continue", "config.json"},
		windows:   []string{".continue", "config.json"},
		winFromHo: true,
	},
	{
		client:    "Zed",
		darwin:    []string{".config", "zed", "settings.json"},
		linux:     []string{".config", "zed", "settings.json"},
		windows:   []string{".config", "zed", "settings.json"},
		winFromHo: true,
	},
	{
		client:    "Gemini CLI",
		darwin:    []string{".gemini", "settings.json"},
		linux:     []string{".gemini", "settings.json"},
		windows:   []string{".gemini", "settings.json"},
		winFromHo: true,
	},
	{
		client:    "Goose",
		darwin:    []string{".config", "goose", "config.yaml"},
		linux:     []string{".config", "goose", "config.yaml"},
		windows:   []string{".config", "goose", "config.yaml"},
		winFromHo: true,
	},
	{
		client:    "Amazon Q",
		darwin:    []string{".aws", "amazonq", "mcp.json"},
		linux:     []string{".aws", "amazonq", "mcp.json"},
		windows:   []string{".aws", "amazonq", "mcp.json"},
		winFromHo: true,
	},
	{
		client:  "Claude Desktop (Roaming)",
		windows: []string{"Claude", "claude_desktop_config.json"},
	},
	{
		client:    "LM Studio",
		darwin:    []string{".lmstudio", "mcp.json"},
		linux:     []string{".lmstudio", "mcp.json"},
		windows:   []string{".lmstudio", "mcp.json"},
		winFromHo: true,
	},
	{
		client:    "Witsy",
		darwin:    []string{".witsy", "settings.json"},
		linux:     []string{".witsy", "settings.json"},
		windows:   []string{".witsy", "settings.json"},
		winFromHo: true,
	},
	{
		client:    "Cody",
		darwin:    []string{".config", "Cody", "mcp.json"},
		linux:     []string{".config", "Cody", "mcp.json"},
		windows:   []string{"Cody", "mcp.json"},
		winFromHo: false,
	},
	{
		client:    "BoltAI",
		darwin:    []string{".boltai", "mcp.json"},
		linux:     []string{".boltai", "mcp.json"},
		windows:   []string{".boltai", "mcp.json"},
		winFromHo: true,
	},
}

// KnownClientConfigs returns the candidate MCP client config locations for the
// given environment. It is pure: it does not touch the filesystem, so all
// candidates are returned regardless of existence. Results are sorted by client
// name for deterministic output.
func KnownClientConfigs(env ClientEnv) []MCPClientConfig {
	var out []MCPClientConfig
	for _, s := range clientSpecs {
		var segs []string
		base := env.Home
		switch env.GOOS {
		case "darwin":
			segs = s.darwin
		case "windows":
			segs = s.windows
			if !s.winFromHo && env.AppData != "" {
				base = env.AppData
			}
		default:
			segs = s.linux
		}
		if len(segs) == 0 {
			continue
		}
		// Join with the separator of the TARGET OS (env.GOOS), not the host's.
		// KnownClientConfigs is GOOS-parameterized, so filepath.Join (which uses
		// the running host's separator) would produce wrong paths when the host
		// OS differs from env.GOOS — e.g. on a Windows CI runner evaluating the
		// darwin/linux cases.
		sep := "/"
		if env.GOOS == "windows" {
			sep = `\`
		}
		out = append(out, MCPClientConfig{
			Client: s.client,
			Path:   base + sep + strings.Join(segs, sep),
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Client < out[j].Client })
	return out
}

// ResolveExistingClientConfigs returns the subset of known client configs that
// exist on disk for the current process environment.
func ResolveExistingClientConfigs() []MCPClientConfig {
	return resolveExisting(CurrentClientEnv(), func(p string) bool {
		info, err := os.Stat(p)
		return err == nil && !info.IsDir()
	})
}

func resolveExisting(env ClientEnv, exists func(string) bool) []MCPClientConfig {
	var out []MCPClientConfig
	for _, c := range KnownClientConfigs(env) {
		if exists(c.Path) {
			out = append(out, c)
		}
	}
	return out
}
