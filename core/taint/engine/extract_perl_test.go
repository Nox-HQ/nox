package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractPerlSubParamsAndCall pins the core recognizer shapes for Perl: a
// `sub name { my ($a) = @_; ... }` header-ish body, an assignment, and a call
// that reads the assigned variable, with sigils stripped.
func TestExtractPerlSubParamsAndCall(t *testing.T) {
	src := []byte(`sub handle {
    my $cmd = $ENV{CMD};
    system("echo " . $cmd);
}
`)
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "handle")
	sink := stmtWithCall(t, u, "system")
	found := false
	for _, r := range sink.reads {
		if r == "cmd" {
			found = true
		}
	}
	if !found {
		t.Errorf("system stmt reads = %v, want to include cmd (sigil stripped)", sink.reads)
	}
}

// TestExtractPerlMyAssignmentSigilStripped: `my $cmd = ...` yields an assignment
// to the bare name `cmd` (the `my` keyword and `$` sigil are stripped).
func TestExtractPerlMyAssignment(t *testing.T) {
	src := []byte(`my $cmd = $ENV{CMD};`)
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "")
	found := false
	for i := range u.stmts {
		if u.stmts[i].assigns == "cmd" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no assignment to bare `cmd` found: %+v", u.stmts)
	}
}

// TestExtractPerlEnvSource: `$ENV{FOO}` is a hash-index source read; the read
// must surface `ENV` so the catalog source resolves.
func TestExtractPerlEnvSource(t *testing.T) {
	src := []byte(`my $x = $ENV{PATH};`)
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "")
	var assign stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "x" {
			assign = u.stmts[i]
		}
	}
	if assign.assigns != "x" {
		t.Fatalf("no assignment to x found: %+v", u.stmts)
	}
	saw := false
	for _, r := range assign.reads {
		if r == "ENV" {
			saw = true
		}
	}
	for _, c := range assign.chains {
		if c == "ENV" {
			saw = true
		}
	}
	if !saw {
		t.Errorf("assignment reads/chains = %v/%v, want to include ENV", assign.reads, assign.chains)
	}
}

// TestExtractPerlArgvSource: `$ARGV[0]` reads the ARGV source.
func TestExtractPerlArgvSource(t *testing.T) {
	src := []byte(`my $x = $ARGV[0];`)
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "")
	var assign stmtDraft
	for i := range u.stmts {
		if u.stmts[i].assigns == "x" {
			assign = u.stmts[i]
		}
	}
	saw := false
	for _, r := range assign.reads {
		if r == "ARGV" {
			saw = true
		}
	}
	if !saw {
		t.Errorf("assignment reads = %v, want to include ARGV", assign.reads)
	}
}

// TestExtractPerlMethodArrow: `$dbh->do(...)` normalizes to the dotted chain
// `dbh.do` so the catalog resolves the method suffix.
func TestExtractPerlMethodArrow(t *testing.T) {
	src := []byte(`my $r = $dbh->do("SELECT $q");`)
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "dbh.do")
	if sink.line == 0 {
		t.Fatalf("method-arrow call $dbh->do not normalized to dbh.do: %+v", u.stmts)
	}
}

// TestExtractPerlParenlessCall: `system "cmd $x"` is recognized as a call to
// `system`.
func TestExtractPerlParenlessCall(t *testing.T) {
	src := []byte(`my $x = $ENV{H};
system "ping $x";`)
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "system")
	if sink.line == 0 {
		t.Fatalf("paren-less system call not recognized: %+v", u.stmts)
	}
}

// TestExtractPerlBacktickCommand: a backtick command literal is a
// command-injection sink whose tainted argument is the interpolated variable.
func TestExtractPerlBacktickCommand(t *testing.T) {
	src := []byte(`my $t = $ENV{TARGET};
my $out = ` + "`traceroute $t`" + `;`)
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "")
	sink := stmtWithCall(t, u, "`")
	if sink.line == 0 {
		t.Fatalf("backtick command literal not recognized as a sink: %+v", u.stmts)
	}
	found := false
	for _, r := range sink.reads {
		if r == "t" {
			found = true
		}
	}
	if !found {
		t.Errorf("backtick sink reads = %v, want to include t", sink.reads)
	}
}
