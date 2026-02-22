package main

import (
	"sort"
	"testing"
)

func TestTaintState_MarkAndGet(t *testing.T) {
	state := NewTaintState()

	src := TaintSource{
		VarName: "id",
		Line:    5,
		Kind:    "http_query",
		Expr:    "r.URL.Query.Get",
	}
	state.Mark("id", src)

	if !state.IsTainted("id") {
		t.Error("expected id to be tainted")
	}

	got, ok := state.Get("id")
	if !ok {
		t.Fatal("expected to get taint source for id")
	}
	if got.Kind != "http_query" {
		t.Errorf("expected kind http_query, got %q", got.Kind)
	}
	if got.Line != 5 {
		t.Errorf("expected line 5, got %d", got.Line)
	}
}

func TestTaintState_Clear(t *testing.T) {
	state := NewTaintState()
	state.Mark("x", TaintSource{VarName: "x", Line: 1, Kind: "env_var"})

	if !state.IsTainted("x") {
		t.Fatal("expected x to be tainted before clear")
	}

	state.Clear("x")

	if state.IsTainted("x") {
		t.Error("expected x to not be tainted after clear")
	}
}

func TestTaintState_Reset(t *testing.T) {
	state := NewTaintState()
	state.Mark("a", TaintSource{VarName: "a", Line: 1, Kind: "http_body"})
	state.Mark("b", TaintSource{VarName: "b", Line: 2, Kind: "cli_arg"})

	state.Reset()

	if state.IsTainted("a") || state.IsTainted("b") {
		t.Error("expected all taint cleared after reset")
	}
}

func TestTaintState_TaintedVars(t *testing.T) {
	state := NewTaintState()
	state.Mark("x", TaintSource{VarName: "x", Line: 1, Kind: "env_var"})
	state.Mark("y", TaintSource{VarName: "y", Line: 2, Kind: "http_query"})

	vars := state.TaintedVars()
	sort.Strings(vars)

	if len(vars) != 2 {
		t.Fatalf("expected 2 tainted vars, got %d", len(vars))
	}
	if vars[0] != "x" || vars[1] != "y" {
		t.Errorf("expected [x, y], got %v", vars)
	}
}

func TestTaintState_NotTainted(t *testing.T) {
	state := NewTaintState()

	if state.IsTainted("nonexistent") {
		t.Error("expected nonexistent var to not be tainted")
	}

	_, ok := state.Get("nonexistent")
	if ok {
		t.Error("expected Get to return false for nonexistent var")
	}
}

func TestMatchGoSource(t *testing.T) {
	tests := []struct {
		chain string
		want  bool
		kind  string
	}{
		{"r.URL.Query.Get", true, "http_query"},
		{"r.FormValue", true, "http_body"},
		{"r.Header.Get", true, "http_header"},
		{"os.Getenv", true, "env_var"},
		{"os.Args", true, "cli_arg"},
		{"fmt.Println", false, ""},
		{"db.Query", false, ""},
	}

	for _, tt := range tests {
		kind, matched := MatchGoSource(tt.chain)
		if matched != tt.want {
			t.Errorf("MatchGoSource(%q) = %v, want %v", tt.chain, matched, tt.want)
		}
		if matched && kind != tt.kind {
			t.Errorf("MatchGoSource(%q) kind = %q, want %q", tt.chain, kind, tt.kind)
		}
	}
}

func TestMatchGoSink(t *testing.T) {
	tests := []struct {
		chain  string
		want   bool
		ruleID string
	}{
		{"db.Exec", true, "TAINT-001"},
		{"db.Query", true, "TAINT-001"},
		{"exec.Command", true, "TAINT-002"},
		{"template.HTML", true, "TAINT-003"},
		{"os.ReadFile", true, "TAINT-004"},
		{"fmt.Println", false, ""},
	}

	for _, tt := range tests {
		ruleID, _, matched := MatchGoSink(tt.chain)
		if matched != tt.want {
			t.Errorf("MatchGoSink(%q) = %v, want %v", tt.chain, matched, tt.want)
		}
		if matched && ruleID != tt.ruleID {
			t.Errorf("MatchGoSink(%q) ruleID = %q, want %q", tt.chain, ruleID, tt.ruleID)
		}
	}
}

func TestMatchTextSource(t *testing.T) {
	tests := []struct {
		line string
		lang string
		want bool
		kind string
	}{
		{`q = request.args.get("q")`, "python", true, "http_query"},
		{`cmd = request.form["cmd"]`, "python", true, "http_body"},
		{`x = os.getenv("KEY")`, "python", true, "env_var"},
		{`x = some_func()`, "python", false, ""},
		{`const q = req.query.id`, "javascript", true, "http_query"},
		{`const b = req.body.data`, "javascript", true, "http_body"},
		{`const x = process.env.KEY`, "javascript", true, "env_var"},
		{`const x = foo.bar`, "javascript", false, ""},
	}

	for _, tt := range tests {
		kind, matched := MatchTextSource(tt.line, tt.lang)
		if matched != tt.want {
			t.Errorf("MatchTextSource(%q, %q) = %v, want %v", tt.line, tt.lang, matched, tt.want)
		}
		if matched && kind != tt.kind {
			t.Errorf("MatchTextSource(%q, %q) kind = %q, want %q", tt.line, tt.lang, kind, tt.kind)
		}
	}
}

func TestMatchTextSink(t *testing.T) {
	tests := []struct {
		line   string
		lang   string
		want   bool
		ruleID string
	}{
		{`cursor.execute("SELECT * FROM x")`, "python", true, "TAINT-001"},
		{`os.system(cmd)`, "python", true, "TAINT-002"},
		{`pickle.loads(data)`, "python", true, "TAINT-005"},
		{`print(x)`, "python", false, ""},
		{`db.query("SELECT " + x)`, "javascript", true, "TAINT-001"},
		{`el.innerHTML = msg`, "javascript", true, "TAINT-003"},
		{`console.log(x)`, "javascript", false, ""},
	}

	for _, tt := range tests {
		ruleID, _, matched := MatchTextSink(tt.line, tt.lang)
		if matched != tt.want {
			t.Errorf("MatchTextSink(%q, %q) = %v, want %v", tt.line, tt.lang, matched, tt.want)
		}
		if matched && ruleID != tt.ruleID {
			t.Errorf("MatchTextSink(%q, %q) ruleID = %q, want %q", tt.line, tt.lang, ruleID, tt.ruleID)
		}
	}
}

func TestIsGoSanitizer(t *testing.T) {
	tests := []struct {
		chain string
		want  bool
	}{
		{"html.EscapeString", true},
		{"strconv.Atoi", true},
		{"url.QueryEscape", true},
		{"fmt.Sprintf", false},
		{"db.Exec", false},
	}

	for _, tt := range tests {
		got := IsGoSanitizer(tt.chain)
		if got != tt.want {
			t.Errorf("IsGoSanitizer(%q) = %v, want %v", tt.chain, got, tt.want)
		}
	}
}

func TestIsTextSanitizer(t *testing.T) {
	tests := []struct {
		line string
		lang string
		want bool
	}{
		{`x = int(y)`, "python", true},
		{`x = bleach.clean(y)`, "python", true},
		{`x = y.strip()`, "python", false},
		{`const x = parseInt(y)`, "javascript", true},
		{`const x = encodeURIComponent(y)`, "javascript", true},
		{`const x = y.trim()`, "javascript", false},
	}

	for _, tt := range tests {
		got := IsTextSanitizer(tt.line, tt.lang)
		if got != tt.want {
			t.Errorf("IsTextSanitizer(%q, %q) = %v, want %v", tt.line, tt.lang, got, tt.want)
		}
	}
}

func TestContainsWord(t *testing.T) {
	tests := []struct {
		s    string
		word string
		want bool
	}{
		{"db.Exec(id)", "id", true},
		{"provider_id", "id", false},
		{"id = 5", "id", true},
		{"(id)", "id", true},
		{"foo", "id", false},
		{"", "id", false},
	}

	for _, tt := range tests {
		got := containsWord(tt.s, tt.word)
		if got != tt.want {
			t.Errorf("containsWord(%q, %q) = %v, want %v", tt.s, tt.word, got, tt.want)
		}
	}
}
