package server

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nox-hq/nox/plugin"
	mcp "go.klarlabs.de/mcp"
)

// executedTool is what one tool returned, reduced to the two things a client
// branches on.
type executedTool struct {
	text    string
	isError bool
}

// executeTool runs a registered tool the way tools/call does and reports the
// text it returned and whether the result was flagged as an error. A bare string
// is what the library sends as a successful text result.
func executeTool(t *testing.T, srv *mcp.Server, name, input string) executedTool {
	t.Helper()
	tool, ok := srv.GetTool(name)
	if !ok {
		t.Fatalf("tool %q is not registered", name)
	}
	out, err := tool.Execute(context.Background(), json.RawMessage(input))
	if err != nil {
		return executedTool{text: err.Error(), isError: true}
	}
	switch v := out.(type) {
	case string:
		return executedTool{text: v}
	case mcp.StructuredResult:
		return executedTool{text: textOf(v), isError: v.IsError}
	case *mcp.StructuredResult:
		return executedTool{text: textOf(*v), isError: v.IsError}
	default:
		data, mErr := json.Marshal(v)
		if mErr != nil {
			t.Fatalf("tool %q returned %T, which does not marshal: %v", name, out, mErr)
		}
		return executedTool{text: string(data)}
	}
}

func registeredServer(t *testing.T, s *Server) *mcp.Server {
	t.Helper()
	srv := mcp.NewServer(mcp.ServerInfo{Name: "nox", Version: "test"})
	s.registerTools(srv)
	return srv
}

// A tool that fails must say so in isError, not only in prose. Twelve tools
// returned the string "Error: ..." from a handler typed (string, error), and the
// library sends a string as a successful text result: an agent that branches on
// isError read a refused plugin_install, a baseline_add that wrote nothing and a
// plugin call that failed as successes. Called with no arguments and no scan
// behind them, most tools have something to refuse; each refusal must be
// flagged.
func TestToolErrorsAreFlagged(t *testing.T) {
	s := New("0.1.0", nil, WithPluginHost(plugin.NewHost()))
	srv := registeredServer(t, s)

	refused := 0
	for _, info := range srv.Tools() {
		got := executeTool(t, srv, info.Name, `{}`)
		if !strings.HasPrefix(got.text, "Error:") {
			continue
		}
		refused++
		if !got.isError {
			t.Errorf("tool %q answered %q without isError", info.Name, got.text)
		}
	}
	if refused < 12 {
		t.Fatalf("only %d tools refused an empty call; the check would be vacuous", refused)
	}
}
