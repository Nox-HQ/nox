// Package mcpshadow detects MCP shadow-server and tool-shadowing risks
// (OWASP MCP09) by relating MCP server definitions across the discovered client
// config inventory.
//
// Two relational signals static per-file rules cannot see:
//
//   - MCP-023 server-name shadowing: the same server name is defined in more
//     than one client config with conflicting definitions. A rogue config can
//     redefine a trusted name (e.g. "github") to point at a different command
//     or endpoint — impersonation.
//   - MCP-024 tool-name shadowing: the same tool name is exposed by more than
//     one distinct server. The host may route a call to the wrong (malicious)
//     server, enabling override/escalation.
//
// Like core/mcppin and the agent-lattice pass, these findings are emitted
// outside the regex engine because they require the full multi-config set.
package mcpshadow

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/mcpconfig"

	"github.com/nox-hq/nox/core/findings"
)

// Server is a single MCP server definition discovered in a client config.
type Server struct {
	Config  string // path of the config the server was found in
	Name    string // server name (key under mcpServers)
	DefHash string // canonical hash of the server definition
	Tools   []string
}

// ParseConfig extracts server definitions from an mcp.json-style config.
//
// It distinguishes three cases the caller must be able to tell apart, because a
// security scanner that treats "could not parse" the same as "nothing here" is
// blind exactly where an attacker wants it to be:
//
//   - valid JSON with an mcpServers object => the servers, nil error.
//   - valid JSON WITHOUT an mcpServers object (some other file) => nil, nil.
//   - malformed JSON (a trailing comma, truncation) => nil, error. Previously
//     this silently returned nil, so a rogue config that fails to parse looked
//     identical to a benign non-MCP file and its shadowing risk was invisible.
//     The caller surfaces this as a visible degradation.
func ParseConfig(path string, content []byte) ([]Server, error) {
	servers, err := mcpconfig.ParseServers(content)
	if err != nil {
		return nil, fmt.Errorf("parsing MCP config %s: %w", path, err)
	}
	if len(servers) == 0 {
		return nil, nil
	}

	names := make([]string, 0, len(servers))
	for name := range servers {
		names = append(names, name)
	}
	sort.Strings(names)

	out := make([]Server, 0, len(names))
	for _, name := range names {
		raw := servers[name]
		out = append(out, Server{
			Config:  path,
			Name:    name,
			DefHash: mcpconfig.CanonicalHash(raw),
			Tools:   extractToolNames(raw),
		})
	}
	return out, nil
}

// Detect returns MCP-023 and MCP-024 findings for the given set of servers
// gathered across one or more client configs.
func Detect(servers []Server) []findings.Finding {
	var out []findings.Finding
	out = append(out, detectServerShadowing(servers)...)
	out = append(out, detectToolShadowing(servers)...)
	return out
}

// detectServerShadowing flags a server name defined with conflicting
// definitions across different configs.
func detectServerShadowing(servers []Server) []findings.Finding {
	type entry struct {
		hashes  map[string]bool
		configs map[string]bool
	}
	byName := map[string]*entry{}
	order := []string{}
	for _, s := range servers {
		e, ok := byName[s.Name]
		if !ok {
			e = &entry{hashes: map[string]bool{}, configs: map[string]bool{}}
			byName[s.Name] = e
			order = append(order, s.Name)
		}
		e.hashes[s.DefHash] = true
		e.configs[s.Config] = true
	}

	var out []findings.Finding
	for _, name := range order {
		e := byName[name]
		// Conflicting definitions across more than one config => impersonation.
		if len(e.hashes) > 1 && len(e.configs) > 1 {
			out = append(out, findings.Finding{
				RuleID:     "MCP-023",
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceMedium,
				Location:   findings.Location{FilePath: sortedFirst(e.configs), StartLine: 1, EndLine: 1},
				Message: fmt.Sprintf(
					"MCP server %q is defined with conflicting definitions across "+
						"%d client configs (%s). A config that redefines a trusted "+
						"server name is shadow/impersonation (OWASP MCP09) — the host "+
						"may launch a different server than the one you approved.",
					name, len(e.configs), joinSorted(e.configs)),
				Metadata: map[string]string{
					"cwe":       "CWE-300",
					"server":    name,
					"owasp-mcp": "MCP09",
					"owasp-asi": "ASI04",
					"detector":  "server-shadowing",
				},
			})
		}
	}
	return out
}

// detectToolShadowing flags a tool name exposed by more than one distinct
// server.
func detectToolShadowing(servers []Server) []findings.Finding {
	type owner struct{ config, server string }
	byTool := map[string][]owner{}
	order := []string{}
	for _, s := range servers {
		for _, tool := range s.Tools {
			if _, seen := byTool[tool]; !seen {
				order = append(order, tool)
			}
			byTool[tool] = append(byTool[tool], owner{s.Config, s.Name})
		}
	}

	var out []findings.Finding
	for _, tool := range order {
		owners := byTool[tool]
		distinct := map[string]bool{}
		for _, o := range owners {
			distinct[o.server] = true
		}
		if len(distinct) > 1 {
			out = append(out, findings.Finding{
				RuleID:     "MCP-024",
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceMedium,
				Location:   findings.Location{FilePath: owners[0].config, StartLine: 1, EndLine: 1},
				Message: fmt.Sprintf(
					"Tool %q is exposed by %d different MCP servers (%s). Tool-name "+
						"shadowing lets a malicious server override a trusted tool "+
						"(OWASP MCP09). Namespace tools per server and pin which server "+
						"owns each tool name.",
					tool, len(distinct), joinServers(distinct)),
				Metadata: map[string]string{
					"cwe":       "CWE-300",
					"tool":      tool,
					"owasp-mcp": "MCP09",
					"owasp-asi": "ASI04",
					"detector":  "tool-shadowing",
				},
			})
		}
	}
	return out
}

// extractToolNames pulls tool names from a server definition's "tools" field,
// supporting both an array of strings and an array of objects with a "name".
func extractToolNames(raw json.RawMessage) []string {
	var def struct {
		Tools json.RawMessage `json:"tools"`
	}
	if err := json.Unmarshal(raw, &def); err != nil || len(def.Tools) == 0 {
		return nil
	}

	// Try []string first.
	var strs []string
	if err := json.Unmarshal(def.Tools, &strs); err == nil {
		return strs
	}

	// Then []{name: string}.
	var objs []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(def.Tools, &objs); err == nil {
		out := make([]string, 0, len(objs))
		for _, o := range objs {
			if o.Name != "" {
				out = append(out, o.Name)
			}
		}
		return out
	}
	return nil
}

func sortedKeys(m map[string]bool) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func sortedFirst(m map[string]bool) string {
	keys := sortedKeys(m)
	if len(keys) == 0 {
		return ""
	}
	return keys[0]
}

func joinSorted(m map[string]bool) string {
	return strings.Join(sortedKeys(m), ", ")
}

func joinServers(m map[string]bool) string {
	return strings.Join(sortedKeys(m), ", ")
}
