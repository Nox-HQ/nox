package mcpconfig

import (
	"encoding/json"
	"fmt"
	"path"
	"strings"
)

// DefaultServersKey is the object key most MCP clients keep servers under
// (Claude Desktop, Claude Code's .mcp.json, Cursor, Windsurf, Cline, Gemini).
const DefaultServersKey = "mcpServers"

func normalizePath(p string) string {
	return strings.ToLower(strings.ReplaceAll(p, `\`, "/"))
}

// ServersKey returns the top-level key that holds server definitions in the
// config at p. Clients disagree: VS Code uses `servers`, Zed uses
// `context_servers`, nearly everyone else `mcpServers`.
//
// The key is chosen from the PATH, never from the content. `servers` is a
// common key in unrelated JSON (inventories, deploy manifests, a Prometheus
// target list), so "any file with a servers object" would manufacture MCP
// servers out of files that have nothing to do with MCP. Only a file that the
// client's own convention puts in that location is read under that client's key.
func ServersKey(p string) string {
	segs := strings.Split(normalizePath(p), "/")
	n := len(segs)
	base := segs[n-1]
	parent, grand := "", ""
	if n >= 2 {
		parent = segs[n-2]
	}
	if n >= 3 {
		grand = segs[n-3]
	}
	switch {
	// <repo>/.vscode/mcp.json, and the user-level <Code>/User/mcp.json.
	case base == "mcp.json" && parent == ".vscode":
		return "servers"
	case base == "mcp.json" && parent == "user" &&
		(grand == "code" || grand == "code - insiders" || grand == "vscodium"):
		return "servers"
	// <repo>/.zed/settings.json and ~/.config/zed/settings.json.
	case base == "settings.json" && (parent == ".zed" || parent == "zed"):
		return "context_servers"
	}
	return DefaultServersKey
}

// ParseServersAt is ParseServers for the config at p: it reads the key that the
// client owning that path uses. Same contract: valid JSON without the key is an
// empty map and no error; malformed JSON is an error.
func ParseServersAt(p string, content []byte) (map[string]json.RawMessage, error) {
	var top map[string]json.RawMessage
	if err := json.Unmarshal(content, &top); err != nil {
		return nil, fmt.Errorf("parsing mcp config: %w", err)
	}
	raw, ok := top[ServersKey(p)]
	if !ok {
		return nil, nil
	}
	var servers map[string]json.RawMessage
	if err := json.Unmarshal(raw, &servers); err != nil {
		// The key is present but is not an object (for example `servers: []`).
		// That is not an MCP server table; it is not a parse failure of the file.
		return nil, nil
	}
	return servers, nil
}

// HasServersKey is a cheap structural test that also holds for JSON that does
// not parse: does the content carry the servers key for path p?
func HasServersKey(p string, content []byte) bool {
	return strings.Contains(string(content), `"`+ServersKey(p)+`"`)
}

// Launch is how a server definition says it is started or reached.
type Launch struct {
	Command string
	Args    []string
	URL     string
}

// ParseLaunch reads command, args and url from one server definition. `command`
// is a string in most clients and an object `{path, args}` in Zed's
// context_servers; both give the same Launch. A definition that does not decode
// returns an error and a zero Launch.
func ParseLaunch(raw json.RawMessage) (Launch, error) {
	var def struct {
		Command json.RawMessage `json:"command"`
		Args    []string        `json:"args"`
		URL     string          `json:"url"`
	}
	if err := json.Unmarshal(raw, &def); err != nil {
		return Launch{}, err
	}
	l := Launch{Args: def.Args, URL: def.URL}
	if len(def.Command) == 0 {
		return l, nil
	}
	var s string
	if json.Unmarshal(def.Command, &s) == nil {
		l.Command = s
		return l, nil
	}
	var obj struct {
		Path string   `json:"path"`
		Args []string `json:"args"`
	}
	if err := json.Unmarshal(def.Command, &obj); err != nil {
		return Launch{}, err
	}
	l.Command = obj.Path
	if len(l.Args) == 0 {
		l.Args = obj.Args
	}
	return l, nil
}

// IsConfigPath reports whether p names an MCP client config by location alone:
// mcp.json in any directory, *.mcp.json, the named client files, and Zed's
// settings.json under .zed or zed.
func IsConfigPath(p string) bool {
	base := path.Base(normalizePath(p))
	switch base {
	case "mcp.json", "claude_desktop_config.json", "cline_mcp_settings.json", "mcp_config.json":
		return true
	}
	return strings.HasSuffix(base, ".mcp.json") || ServersKey(p) == "context_servers"
}
