package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeRuby is the end-to-end helper for Ruby: source → units → flows, using
// AnalyzeFile so same-file interprocedural helpers are exercised too.
func analyzeRuby(t *testing.T, src string) []taintFlowIDs {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.rb", lexctx.LangRuby, []byte(src))
	flows := eng.AnalyzeFile(units)
	out := make([]taintFlowIDs, 0, len(flows))
	for i := range flows {
		out = append(out, taintFlowIDs{rule: flows[i].Sink.RuleID, class: string(flows[i].Sink.VulnClass)})
	}
	return out
}

type taintFlowIDs struct {
	rule  string
	class string
}

func rubyHasRule(flows []taintFlowIDs, id string) bool {
	for _, f := range flows {
		if f.rule == id {
			return true
		}
	}
	return false
}

// TestStructuralRubyTruePositives exercises the headline Ruby injection classes
// end to end, asserting the expected rule ID fires.
func TestStructuralRubyTruePositives(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want string
	}{
		{
			name: "command injection via system paren-less",
			src: `def handle
  cmd = params[:cmd]
  system "echo #{cmd}"
end
`,
			want: "TAINT-002",
		},
		{
			name: "command injection via backtick",
			src: `def handle
  host = params[:host]
  out = ` + "`ping #{host}`" + `
end
`,
			want: "TAINT-002",
		},
		{
			name: "command injection via %x percent-literal",
			src: `def handle
  target = params[:target]
  out = %x(ls #{target})
end
`,
			want: "TAINT-002",
		},
		{
			name: "sql injection via ActiveRecord where string interp",
			src: `def handle
  id = params[:id]
  User.where("id = #{id}")
end
`,
			want: "TAINT-001",
		},
		{
			name: "path traversal via File.read",
			src: `def handle
  name = params[:file]
  File.read(name)
end
`,
			want: "TAINT-004",
		},
		{
			name: "ssrf via Net::HTTP.get",
			src: `def handle
  url = params[:url]
  Net::HTTP.get(url)
end
`,
			want: "TAINT-006",
		},
		{
			name: "unsafe deserialization via Marshal.load",
			src: `def handle
  blob = params[:data]
  Marshal.load(blob)
end
`,
			want: "TAINT-005",
		},
		{
			name: "code injection via eval",
			src: `def handle
  code = params[:code]
  eval(code)
end
`,
			want: "TAINT-005",
		},
		{
			name: "xss via ERB render inline (html_safe)",
			src: `def handle
  name = params[:name]
  html = name.html_safe
end
`,
			want: "TAINT-003",
		},
		{
			name: "ssti/xss via render inline: interpolation",
			src: `def show
  name = params[:name]
  render inline: "<h1>Hello #{name}</h1>"
end
`,
			want: "TAINT-003",
		},
		{
			name: "ssti/xss via render text: interpolation",
			src: `def show
  val = params[:v]
  render text: "Value: #{val}"
end
`,
			want: "TAINT-003",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeRuby(t, tt.src)
			if !rubyHasRule(flows, tt.want) {
				t.Errorf("want rule %s to fire, got flows %+v", tt.want, flows)
			}
		})
	}
}

// TestStructuralRubyCleanNoFlow verifies safe/sanitized code does NOT fire — the
// precision guarantee.
func TestStructuralRubyCleanNoFlow(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "parameterized ActiveRecord where (placeholder)",
			src: `def handle
  id = params[:id]
  User.where("id = ?", id)
end
`,
		},
		{
			name: "integer coercion sanitizes",
			src: `def handle
  raw = params[:id]
  id = Integer(raw)
  system "echo #{id}"
end
`,
		},
		{
			name: "shellescape sanitizes command injection",
			src: `def handle
  raw = params[:host]
  safe = Shellwords.escape(raw)
  system "ping #{safe}"
end
`,
		},
		{
			name: "no source: constant command",
			src: `def handle
  system "ls -la"
end
`,
		},
		{
			name: "html escape sanitizes xss",
			src: `def handle
  raw = params[:name]
  safe = CGI.escapeHTML(raw)
  out = safe.html_safe
end
`,
		},
		{
			name: "render plain: is auto-escaped (no ssti sink)",
			src: `def show
  output = params[:o]
  render plain: output
end
`,
		},
		{
			name: "render json: is auto-escaped (no ssti sink)",
			src: `def show
  data = params[:d]
  render json: data
end
`,
		},
		{
			name: "render inline: sanitized with html_escape stays clean",
			src: `def show
  raw = params[:name]
  name = CGI.escapeHTML(raw)
  render inline: "<h1>Hello #{name}</h1>"
end
`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeRuby(t, tt.src)
			if len(flows) != 0 {
				t.Errorf("clean sample must not fire, got %+v", flows)
			}
		})
	}
}
