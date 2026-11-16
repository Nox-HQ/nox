package ai

import (
	"bytes"
	"path/filepath"
	"strings"
)

// MCP-011 reports tool metadata that stages credential exfiltration. Its
// pattern is prose — an exfiltration verb followed by a secret noun — and the
// rule scans general source because a tool's description is a string in the
// code that registers it.
//
// A UI component holds a different kind of prose: the text a person reads.
// "Upload the credential again to restart" is an instruction to the user in
// front of the form, and matched MCP-011 twice in RAGFlow's data-source
// settings (#1090). Neither file defines a tool.
//
// So in a JSX/TSX component the rule needs the file to define a tool at all.
// The markers are what every tool definition carries: an MCP or WebMCP
// registration (registerTool, navigator.modelContext, addTool, server.tool),
// an input schema, an AI SDK tool() call, or the word mcp. A component that
// registers a WebMCP tool keeps the rule; one that only renders a form does not.
//
// The gate is limited to .jsx/.tsx. Server code (.ts, .js, .go, .py) is where
// tool metadata is usually declared, and there the rule is unchanged.

// uiComponentExts are the extensions of JSX component files.
var uiComponentExts = map[string]bool{".tsx": true, ".jsx": true}

// toolDefinitionMarkers are lower-case substrings at least one of which a file
// defining an agent tool contains.
var toolDefinitionMarkers = [][]byte{
	[]byte("mcp"), []byte("modelcontext"), []byte("registertool"),
	[]byte("addtool"), []byte("inputschema"), []byte("input_schema"),
	[]byte("tool("),
}

// isUIComponentWithoutTools reports whether path is a JSX/TSX component whose
// content defines no agent tool.
func isUIComponentWithoutTools(path string, content []byte) bool {
	if !uiComponentExts[strings.ToLower(filepath.Ext(path))] {
		return false
	}
	lower := bytes.ToLower(content)
	for _, m := range toolDefinitionMarkers {
		if bytes.Contains(lower, m) {
			return false
		}
	}
	return true
}
