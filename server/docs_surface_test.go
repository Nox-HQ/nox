package server

import (
	"encoding/json"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	mcp "go.klarlabs.de/mcp"
)

// The README said `nox serve` starts "10 read-only tools and 5 resources" and
// tabulated eleven tools, two of which (plugin.list, plugin.call_tool) that
// command never registers. It registers 28 tools and 13 resources. A table in
// prose drifts the day after it is written, so these tests read the documents
// and compare them with what the server registers.

// servedByNoxServe is the surface of the server exactly as `nox serve` builds
// it: server.New with no options.
func servedByNoxServe(t *testing.T) *mcp.Server {
	t.Helper()
	s := New("test", nil)
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	s.registerTools(srv)
	s.registerResources(srv)
	return srv
}

var backticked = regexp.MustCompile("`([^`]+)`")

// tableUnder returns the rows of the first markdown table under the "### sub"
// heading inside the "## section" of a document, header and separator dropped,
// each row split into trimmed cells.
func tableUnder(t *testing.T, path, section, sub string) [][]string {
	t.Helper()
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var rows [][]string
	inSection, inSub := false, false
	for _, line := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(line, "## "):
			inSection, inSub = strings.TrimSpace(line[3:]) == section, false
			continue
		case strings.HasPrefix(line, "### "):
			inSub = inSection && strings.TrimSpace(line[4:]) == sub
			continue
		}
		if !inSub || !strings.HasPrefix(line, "|") {
			if inSub && len(rows) > 0 && strings.TrimSpace(line) == "" {
				inSub = false // the table ended
			}
			continue
		}
		// An escaped pipe is part of a cell, not a column break.
		cells := strings.Split(strings.ReplaceAll(strings.Trim(strings.TrimSpace(line), "|"), `\|`, "\x00"), "|")
		for i := range cells {
			cells[i] = strings.TrimSpace(strings.ReplaceAll(cells[i], "\x00", "|"))
		}
		rows = append(rows, cells)
	}
	if len(rows) < 3 {
		t.Fatalf("%s: found no table under %q / %q; the guard below would be vacuous", path, section, sub)
	}
	return rows[2:]
}

// firstBackticked is the name a row is about: the first `code` span of its
// first cell.
func firstBackticked(t *testing.T, path string, row []string) string {
	t.Helper()
	m := backticked.FindStringSubmatch(row[0])
	if m == nil {
		t.Fatalf("%s: a table row names nothing in its first cell: %q", path, row)
	}
	return m[1]
}

func diffSets(documented, registered []string) (onlyDocumented, onlyRegistered []string) {
	doc, reg := map[string]bool{}, map[string]bool{}
	for _, d := range documented {
		doc[d] = true
	}
	for _, r := range registered {
		reg[r] = true
		if !doc[r] {
			onlyRegistered = append(onlyRegistered, r)
		}
	}
	for _, d := range documented {
		if !reg[d] {
			onlyDocumented = append(onlyDocumented, d)
		}
	}
	sort.Strings(onlyDocumented)
	sort.Strings(onlyRegistered)
	return onlyDocumented, onlyRegistered
}

var mcpDocs = []string{"../README.md", "../docs/usage.md"}

func TestDocumentedToolsAreTheRegisteredTools(t *testing.T) {
	srv := servedByNoxServe(t)
	var registered []string
	for _, ti := range srv.Tools() {
		registered = append(registered, ti.Name)
	}
	for _, path := range mcpDocs {
		var documented []string
		for _, row := range tableUnder(t, path, "MCP Server", "Tools") {
			documented = append(documented, firstBackticked(t, path, row))
		}
		ghost, missing := diffSets(documented, registered)
		if len(ghost) > 0 {
			t.Errorf("%s documents tools `nox serve` does not register: %v", path, ghost)
		}
		if len(missing) > 0 {
			t.Errorf("%s leaves out tools `nox serve` registers: %v", path, missing)
		}
	}
}

func TestDocumentedResourcesAreTheRegisteredResources(t *testing.T) {
	srv := servedByNoxServe(t)
	var registered []string
	for _, r := range srv.Resources() {
		registered = append(registered, r.URITemplate)
	}
	for _, path := range mcpDocs {
		var documented []string
		for _, row := range tableUnder(t, path, "MCP Server", "Resources") {
			documented = append(documented, firstBackticked(t, path, row))
		}
		ghost, missing := diffSets(documented, registered)
		if len(ghost) > 0 {
			t.Errorf("%s documents resources `nox serve` does not register: %v", path, ghost)
		}
		if len(missing) > 0 {
			t.Errorf("%s leaves out resources `nox serve` registers: %v", path, missing)
		}
	}
}

// The README's Parameters column is a list of `name` spans, so it can be held
// to the published input schema: a parameter the tool does not take, or one it
// takes that the table leaves out, fails here.
func TestReadmeToolParametersAreTheSchemaProperties(t *testing.T) {
	srv := servedByNoxServe(t)
	properties := map[string][]string{}
	for _, ti := range srv.Tools() {
		raw, err := json.Marshal(ti.InputSchema)
		if err != nil {
			t.Fatal(err)
		}
		var schema struct {
			Properties map[string]json.RawMessage `json:"properties"`
		}
		if err := json.Unmarshal(raw, &schema); err != nil {
			t.Fatalf("tool %q: input schema: %v", ti.Name, err)
		}
		for name := range schema.Properties {
			properties[ti.Name] = append(properties[ti.Name], name)
		}
	}
	const path = "../README.md"
	for _, row := range tableUnder(t, path, "MCP Server", "Tools") {
		tool := firstBackticked(t, path, row)
		if len(row) < 2 {
			t.Fatalf("%s: row for %q has no Parameters cell", path, tool)
		}
		var documented []string
		for _, m := range backticked.FindAllStringSubmatch(row[1], -1) {
			documented = append(documented, m[1])
		}
		ghost, missing := diffSets(documented, properties[tool])
		if len(ghost) > 0 {
			t.Errorf("%s: tool %q is documented with parameters it does not take: %v", path, tool, ghost)
		}
		if len(missing) > 0 {
			t.Errorf("%s: tool %q takes parameters the table leaves out: %v", path, tool, missing)
		}
	}
}

// A number in a sentence is the first thing to go stale.
func TestReadmeDoesNotCountTheSurface(t *testing.T) {
	raw, err := os.ReadFile("../README.md")
	if err != nil {
		t.Fatal(err)
	}
	if m := regexp.MustCompile(`\d+ (read-only )?tools and \d+ resources`).Find(raw); m != nil {
		t.Errorf("README counts the MCP surface in prose (%q); the tables under MCP Server are checked against the server, a count is not", m)
	}
}
