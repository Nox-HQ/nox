package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeLua is the end-to-end helper for Lua: source → units → flows.
func analyzeLua(t *testing.T, src string) []taintFlowIDs {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.lua", lexctx.LangLua, []byte(src))
	flows := eng.AnalyzeFile(units)
	out := make([]taintFlowIDs, 0, len(flows))
	for i := range flows {
		out = append(out, taintFlowIDs{rule: flows[i].Sink.RuleID, class: string(flows[i].Sink.VulnClass)})
	}
	return out
}

func luaHasRule(flows []taintFlowIDs, id string) bool {
	for _, f := range flows {
		if f.rule == id {
			return true
		}
	}
	return false
}

// TestStructuralLuaTruePositives exercises the headline Lua injection classes end
// to end, asserting the expected rule ID fires.
func TestStructuralLuaTruePositives(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "command injection via os.execute of arg",
			src:  "local cmd = arg[1]\nos.execute(\"echo \" .. cmd)\n",
			want: "TAINT-002",
		},
		{
			name: "command injection via io.popen of env",
			src:  "local host = os.getenv(\"HOST\")\nlocal h = io.popen(\"ping \" .. host)\n",
			want: "TAINT-002",
		},
		{
			name: "code injection via loadstring of stdin",
			src:  "local code = io.read()\nloadstring(code)()\n",
			want: "TAINT-005",
		},
		{
			name: "path traversal via io.open of arg",
			src:  "local p = arg[1]\nlocal f = io.open(p)\n",
			want: "TAINT-004",
		},
		{
			name: "sql injection via conn:execute of resty request arg",
			src:  "local id = ngx.req.get_uri_args().id\nconn:execute(\"SELECT * FROM t WHERE id = \" .. id)\n",
			want: "TAINT-001",
		},
		{
			name: "ssrf via http.request of a tainted url",
			src:  "local u = ngx.req.get_uri_args().url\nhttp.request(u)\n",
			want: "TAINT-006",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeLua(t, tt.src)
			if !luaHasRule(flows, tt.want) {
				t.Errorf("want rule %s in flows, got %+v", tt.want, flows)
			}
		})
	}
}

// TestStructuralLuaCleanNoFlow asserts the SAFE counterparts do NOT fire: a
// tonumber-coerced value into a command sink, and a constant path into io.open.
func TestStructuralLuaCleanNoFlow(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "tonumber sanitizes before os.execute",
			src:  "local raw = arg[1]\nlocal n = tonumber(raw)\nos.execute(\"sleep \" .. n)\n",
		},
		{
			name: "tonumber sanitizes inline at the sink",
			src:  "local raw = arg[1]\nos.execute(\"sleep \" .. tonumber(raw))\n",
		},
		{
			name: "constant path into io.open",
			src:  "local f = io.open(\"/etc/app/config.ini\")\n",
		},
		{
			name: "env used only in a non-sink position",
			src:  "local u = os.getenv(\"USER\")\nprint(u)\n",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeLua(t, tt.src)
			if len(flows) != 0 {
				t.Errorf("expected no flows, got %+v", flows)
			}
		})
	}
}
