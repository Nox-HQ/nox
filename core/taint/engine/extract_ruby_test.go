package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractRubyDefParamsAndCall pins the core recognizer shapes for Ruby: a
// `def name(a, b)` header with positional params, an assignment, and a call that
// reads the assigned variable.
func TestExtractRubyDefParamsAndCall(t *testing.T) {
	src := []byte(`def handle(request)
  cmd = params[:cmd]
  system("echo " + cmd)
end
`)
	units := extractUnits(lexctx.LangRuby, src)
	u := findUnit(t, units, "handle")
	if len(u.params) != 1 || u.params[0] != "request" {
		t.Fatalf("params = %v, want [request]", u.params)
	}
	sink := stmtWithCall(t, u, "system")
	found := false
	for _, r := range sink.reads {
		if r == "cmd" {
			found = true
		}
	}
	if !found {
		t.Errorf("system stmt reads = %v, want to include cmd", sink.reads)
	}
}

// TestExtractRubyParenlessCall verifies a paren-less call (`system "..."`) is
// recognized as a call to `system`.
func TestExtractRubyParenlessCall(t *testing.T) {
	src := []byte(`def handle
  cmd = params[:cmd]
  system "echo #{cmd}"
end
`)
	units := extractUnits(lexctx.LangRuby, src)
	u := findUnit(t, units, "handle")
	if len(u.stmts) == 0 {
		t.Fatalf("no statements extracted")
	}
	sink := stmtWithCall(t, u, "system")
	if sink.line == 0 {
		t.Fatalf("paren-less system call not recognized: %+v", u.stmts)
	}
}

// TestExtractRubyParamsIndexSource: `params[:x]` is a hash-index source read; the
// chain/read must surface `params` so the catalog source resolves.
func TestExtractRubyParamsIndexSource(t *testing.T) {
	src := []byte(`def handle
  name = params[:name]
  x = name
end
`)
	units := extractUnits(lexctx.LangRuby, src)
	u := findUnit(t, units, "handle")
	var assign stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "name" {
			assign = u.stmts[i]
		}
	}
	if assign.assigns != "name" {
		t.Fatalf("no assignment to name found: %+v", u.stmts)
	}
	// `params` must appear either as a read or a chain so resolveSource can match.
	sawParams := false
	for _, r := range assign.reads {
		if r == "params" {
			sawParams = true
		}
	}
	for _, c := range assign.chains {
		if c == "params" || c == "params.name" {
			sawParams = true
		}
	}
	if !sawParams {
		t.Errorf("assignment reads/chains = %v / %v, want to surface params", assign.reads, assign.chains)
	}
}

// TestExtractRubyExplicitReturn: `return x` yields a stmt whose returns lists x.
func TestExtractRubyExplicitReturn(t *testing.T) {
	src := []byte(`def helper(a)
  return a
end
`)
	units := extractUnits(lexctx.LangRuby, src)
	u := findUnit(t, units, "helper")
	sawReturn := false
	for i := range u.stmts {
		for _, r := range u.stmts[i].returns {
			if r == "a" {
				sawReturn = true
			}
		}
	}
	if !sawReturn {
		t.Errorf("no return of a found in %+v", u.stmts)
	}
}

// TestExtractRubyMethodSuffixCall: a chained call `User.where(...)` surfaces the
// `.where` suffix so the catalog SQL sink resolves by suffix.
func TestExtractRubyMethodSuffixCall(t *testing.T) {
	src := []byte(`def handle
  id = params[:id]
  User.where("id = #{id}")
end
`)
	units := extractUnits(lexctx.LangRuby, src)
	u := findUnit(t, units, "handle")
	sawWhere := false
	for i := range u.stmts {
		for _, c := range u.stmts[i].calls {
			if c == "User.where" {
				sawWhere = true
			}
		}
	}
	if !sawWhere {
		t.Errorf("no User.where call found in %+v", u.stmts)
	}
}

// TestExtractRubyRenderInlineSink: `render inline: "...#{x}..."` synthesizes a
// `render_inline` sink call whose tainted argument is the interpolated variable,
// so an SSTI/XSS flow is recognized. The safe auto-escaped forms (`render plain:`,
// `render json:`, `render :template`) must NOT synthesize the sink.
func TestExtractRubyRenderInlineSink(t *testing.T) {
	tests := []struct {
		name     string
		line     string
		wantSink bool
		wantRead string
	}{
		{
			name:     "render inline with interpolation",
			line:     `render inline: "<h1>Hello #{name}</h1>"`,
			wantSink: true,
			wantRead: "name",
		},
		{
			name:     "render inline paren form",
			line:     `render(inline: "<h1>#{name}</h1>")`,
			wantSink: true,
			wantRead: "name",
		},
		{
			name:     "render text with interpolation",
			line:     `render text: "Value: #{val}"`,
			wantSink: true,
			wantRead: "val",
		},
		{
			name:     "render plain is safe (no sink)",
			line:     `render plain: output`,
			wantSink: false,
		},
		{
			name:     "render json is safe (no sink)",
			line:     `render json: data`,
			wantSink: false,
		},
		{
			name:     "render template symbol is safe (no sink)",
			line:     `render :show`,
			wantSink: false,
		},
		{
			name:     "render inline without interpolation (constant, no read)",
			line:     `render inline: "<h1>static</h1>"`,
			wantSink: true, // sink present but no tainted read → won't flow
			wantRead: "",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			src := []byte("def show\n  name = params[:name]\n  val = params[:v]\n  output = params[:o]\n  data = params[:d]\n  " + tt.line + "\nend\n")
			units := extractUnits(lexctx.LangRuby, src)
			u := findUnit(t, units, "show")
			var sink stmtDraft
			for i := range u.stmts {
				for _, c := range u.stmts[i].calls {
					if c == renderInlineSink {
						sink = u.stmts[i]
					}
				}
			}
			hasSink := sink.line != 0
			if hasSink != tt.wantSink {
				t.Fatalf("render_inline sink present = %v, want %v (stmts: %+v)", hasSink, tt.wantSink, u.stmts)
			}
			if tt.wantSink && tt.wantRead != "" {
				found := false
				for _, r := range sink.reads {
					if r == tt.wantRead {
						found = true
					}
				}
				if !found {
					t.Errorf("render_inline sink reads = %v, want to include %q", sink.reads, tt.wantRead)
				}
			}
		})
	}
}
