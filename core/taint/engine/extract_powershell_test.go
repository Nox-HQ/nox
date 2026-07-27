package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractPowerShellParamBlock pins the param(...) block recognizer: the bare
// parameter names (after the $ sigil and [type] accelerators are stripped) become
// the current unit's params.
func TestExtractPowerShellParamBlock(t *testing.T) {
	src := []byte("param(\n  [string]$Name,\n  [int]$Count = 0\n)\n$x = 1\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	if !containsStr(u.params, "Name") || !containsStr(u.params, "Count") {
		t.Errorf("params = %v, want to include [Name Count]", u.params)
	}
}

// TestExtractPowerShellFunctionHeader: a `function Get-Report ($a, $b) { ... }`
// header opens a named unit whose params are the inline list.
func TestExtractPowerShellFunctionHeader(t *testing.T) {
	src := []byte("function Get-Report ($src, $dst) {\n  $x = 1\n}\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "Get-Report")
	if len(u.params) != 2 || u.params[0] != "src" || u.params[1] != "dst" {
		t.Errorf("params = %v, want [src dst]", u.params)
	}
}

// TestExtractPowerShellArgsSource: `$cmd = $args[0]` records `args` as a source
// chain so the engine taints cmd.
func TestExtractPowerShellArgsSource(t *testing.T) {
	src := []byte("$cmd = $args[0]\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	st := stmtWithAssignPS(t, u, "cmd")
	if !containsStr(st.chains, "args") {
		t.Errorf("cmd assignment source chains = %v, want to include args", st.chains)
	}
}

// TestExtractPowerShellEnvSource: `$p = $env:USERPROFILE` records `env` as a
// source chain (the $env: provider shaped to a bare env read).
func TestExtractPowerShellEnvSource(t *testing.T) {
	src := []byte("$p = $env:TARGET\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	st := stmtWithAssignPS(t, u, "p")
	if !containsStr(st.chains, "env") {
		t.Errorf("p assignment source chains = %v, want to include env", st.chains)
	}
}

// TestExtractPowerShellParenlessSink: a paren-less `Invoke-Expression $user`
// records the callee `Invoke_Expression` (hyphen normalized) reading user.
func TestExtractPowerShellParenlessSink(t *testing.T) {
	src := []byte("$user = $args[0]\nInvoke-Expression $user\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "Invoke_Expression")
	if !containsStr(sink.reads, "user") {
		t.Errorf("Invoke_Expression reads = %v, want to include user", sink.reads)
	}
}

// TestExtractPowerShellNamedParamSink: `Invoke-WebRequest -Uri $url` records the
// callee and reads url (the -Uri flag is ignored by the identifier scanner).
func TestExtractPowerShellNamedParamSink(t *testing.T) {
	src := []byte("$url = $args[0]\nInvoke-WebRequest -Uri $url\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "Invoke_WebRequest")
	if !containsStr(sink.reads, "url") {
		t.Errorf("Invoke_WebRequest reads = %v, want to include url", sink.reads)
	}
}

// TestExtractPowerShellAmpInvoke: `& $cmd` is shaped to the synthetic sink
// InvokeOperator reading cmd.
func TestExtractPowerShellAmpInvoke(t *testing.T) {
	src := []byte("$cmd = $args[0]\n& $cmd --flag\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "InvokeOperator")
	if !containsStr(sink.reads, "cmd") {
		t.Errorf("InvokeOperator reads = %v, want to include cmd", sink.reads)
	}
}

// TestExtractPowerShellStaticMember: `[IO.File]::ReadAllText($p)` shapes to
// IO.File.ReadAllText, matched by the .ReadAllText suffix.
func TestExtractPowerShellStaticMember(t *testing.T) {
	src := []byte("$p = $args[0]\n$data = [IO.File]::ReadAllText($p)\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "IO.File.ReadAllText")
	if !containsStr(sink.reads, "p") {
		t.Errorf("ReadAllText reads = %v, want to include p", sink.reads)
	}
}

// TestExtractPowerShellCastSanitizer: `[int]$raw` shapes to int($raw) so the
// numeric cast is recognized as a sanitizer call.
func TestExtractPowerShellCastSanitizer(t *testing.T) {
	src := []byte("$raw = $args[0]\n$id = [int]$raw\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "int")
	if !containsStr(sink.reads, "raw") {
		t.Errorf("int cast reads = %v, want to include raw", sink.reads)
	}
}

// stmtWithAssignPS returns the first statement whose Assigns equals name.
func stmtWithAssignPS(t *testing.T, u unitDraft, name string) stmtDraft {
	t.Helper()
	for i := range u.stmts {
		if u.stmts[i].assigns == name {
			return u.stmts[i]
		}
	}
	t.Fatalf("no assignment to %q in unit %q; stmts=%+v", name, u.funcName, u.stmts)
	return stmtDraft{}
}

// TestExtractPowerShellPipelineSink: `$x | Invoke-Expression` binds $x to the
// cmdlet's PIPELINE input, which is a real argument position — the value is as
// executed as it would be in `Invoke-Expression $x`. The recognizer models the
// pipeline by rewriting it into that positional form. This is the suite's
// documented tp_pipeline_fn.ps1 false negative.
func TestExtractPowerShellPipelineSink(t *testing.T) {
	src := []byte("$payload = $args[0]\n$payload | Invoke-Expression\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "Invoke_Expression")
	if sink.line == 0 {
		t.Fatalf("piped Invoke-Expression not recognized: %+v", u.stmts)
	}
	if !containsStr(sink.reads, "payload") {
		t.Errorf("piped Invoke_Expression reads = %v, want to include payload", sink.reads)
	}
}

// TestExtractPowerShellMultiStagePipeline: a value carried through several
// pipeline stages still reaches the final cmdlet, where the sink is.
func TestExtractPowerShellMultiStagePipeline(t *testing.T) {
	src := []byte("$payload = $args[0]\n$payload | Out-String | Invoke-Expression\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "Invoke_Expression")
	if sink.line == 0 {
		t.Fatalf("final pipeline stage Invoke-Expression not recognized: %+v", u.stmts)
	}
	if !containsStr(sink.reads, "payload") {
		t.Errorf("multi-stage piped Invoke_Expression reads = %v, want to include payload", sink.reads)
	}
}

// TestExtractPowerShellPipeInStringIsNotAPipeline is the precision guard for the
// rewrite above. A `|` inside a STRING — an alternation in a regex literal, the
// shape clean_validated.ps1 uses — is not a pipeline operator. Pipe positions are
// therefore taken from the code view, where string bodies are blanked, never from
// the raw text. Misreading one would splice a sink out of a comparison.
func TestExtractPowerShellPipeInStringIsNotAPipeline(t *testing.T) {
	src := []byte("$action = $args[0]\nif ($action -match '^start|stop$') { Write-Output 'ok' }\n")
	units := extractUnits(lexctx.LangPowerShell, src)
	u := findUnit(t, units, "")
	for _, st := range u.stmts {
		for _, c := range st.calls {
			if c == "stop$'" || c == "stop" {
				t.Errorf("a | inside a string literal was treated as a pipeline: calls = %v", st.calls)
			}
		}
	}
}
