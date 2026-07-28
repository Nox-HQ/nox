package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestSharedStateRubyIvar: a source landing in an @ivar in one method and read
// by a sink in another is a real flow the intraprocedural model could not join.
func TestSharedStateRubyIvar(t *testing.T) {
	src := []byte("class C\n  def capture\n    @cmd = params[:cmd]\n  end\n  def run\n    system @cmd\n  end\nend\n")
	units := extractUnits(lexctx.LangRuby, src)
	u := findUnit(t, units, "run")
	bound := false
	for _, st := range u.stmts {
		if st.assigns == "cmd" {
			bound = true
		}
	}
	if !bound {
		t.Errorf("the @cmd binding was not joined into the reading unit: %+v", u.stmts)
	}
}

// TestSharedStatePerlOurGlobal: the same join for a Perl package global.
func TestSharedStatePerlOurGlobal(t *testing.T) {
	src := []byte("our $PAYLOAD;\nsub stash {\n    $PAYLOAD = $ENV{DATA};\n}\nsub flush {\n    system(\"logger $PAYLOAD\");\n}\n")
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "flush")
	bound := false
	for _, st := range u.stmts {
		if st.assigns == "PAYLOAD" {
			bound = true
		}
	}
	if !bound {
		t.Errorf("the PAYLOAD binding was not joined into the reading sub: %+v", u.stmts)
	}
}

// TestSharedStateIgnoresLocals is the precision guard, and the reason the join
// is safe: only a SYNTACTICALLY shared name participates. Two subs that happen
// to use the same LOCAL name are unrelated and must not be joined, or every
// same-named local in a file would collapse into one variable.
func TestSharedStateIgnoresLocals(t *testing.T) {
	src := []byte("sub a {\n    my $cmd = $ENV{CMD};\n}\nsub b {\n    system(\"run $cmd\");\n}\n")
	units := extractUnits(lexctx.LangPerl, src)
	u := findUnit(t, units, "b")
	for _, st := range u.stmts {
		if st.assigns == "cmd" {
			t.Errorf("a `my` local was joined across subs: %+v", u.stmts)
		}
	}
}

// TestJoinSharedStateDropsSinkArgs: a copied binding is replayed for its taint,
// not re-reported, so a sink inside the binding expression must not fire again
// in every unit that reads the name.
func TestJoinSharedStateDropsSinkArgs(t *testing.T) {
	units := []unitDraft{
		{funcName: "a", stmts: []stmtDraft{{
			assigns:  "G",
			calls:    []string{"system"},
			sinkArgs: map[string]sinkArgDraft{"system": {taintedArgVars: []string{"x"}}},
		}}},
		{funcName: "b", stmts: []stmtDraft{{reads: []string{"G"}}}},
	}
	out := joinSharedState(units, map[string]bool{"G": true})
	for _, st := range out[1].stmts {
		if len(st.sinkArgs) != 0 {
			t.Errorf("copied binding kept sink-arg evidence and would re-report: %+v", st)
		}
	}
}

// TestContainerAssignRoot pins the perl element-assignment binding.
func TestContainerAssignRoot(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"args{cmd}", "args", true},
		{"list[0]", "list", true},
		{"plain", "", false},     // no subscript
		{"a{b}{c}", "", false},   // nested: no single container
		{"a{b}tail", "", false},  // subscript does not end the target
		{"return{x}", "", false}, // keyword root
	} {
		got, ok := containerAssignRoot(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("containerAssignRoot(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}
