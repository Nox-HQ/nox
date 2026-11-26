package treesitter

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"

	"github.com/tetratelabs/wazero"
)

// ADR 0006, rule 1: the embedded modules are the ones SHA256SUMS records, and
// every module SHA256SUMS records is embedded. scripts/treesitter/build.sh
// --check (CI) proves the sums are what pins.json builds.
func TestEmbeddedModulesMatchTheirRecordedSums(t *testing.T) {
	sums, err := embedded.ReadFile("wasm/SHA256SUMS")
	if err != nil {
		t.Fatal(err)
	}
	recorded := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(sums)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) != 2 {
			t.Fatalf("SHA256SUMS line %q is not `<sum>  <file>`", sc.Text())
		}
		recorded[f[1]] = f[0]
	}
	entries, err := embedded.ReadDir("wasm")
	if err != nil {
		t.Fatal(err)
	}
	var seen []string
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".wasm") {
			continue
		}
		b, _ := embedded.ReadFile("wasm/" + e.Name())
		sum := sha256.Sum256(b)
		if got := hex.EncodeToString(sum[:]); got != recorded[e.Name()] {
			t.Errorf("%s: sha256 %s, SHA256SUMS records %q", e.Name(), got, recorded[e.Name()])
		}
		seen = append(seen, e.Name())
	}
	if len(seen) != len(recorded) {
		t.Errorf("embedded %v, SHA256SUMS records %d modules", seen, len(recorded))
	}
	modules := map[string]bool{}
	for _, m := range moduleOf {
		modules[m+".wasm"] = true
	}
	for m := range modules {
		if _, ok := recorded[m]; !ok {
			t.Errorf("a language maps to %s, which is not embedded", m)
		}
	}
}

// The guest is granted nothing a parse could use to observe the host: the
// only imports are the four WASI functions the stubs answer with ENOSYS. The
// Swift grammar's scanner calls exit(1) when its one allocation fails, so
// swift.wasm also imports proc_exit, which the host ends the guest with: it
// reads nothing from the host.
func TestModulesImportOnlyTheStubbedFunctions(t *testing.T) {
	ctx := context.Background()
	rt := wazero.NewRuntime(ctx)
	defer func() { _ = rt.Close(ctx) }()
	want := []string{"clock_time_get", "fd_close", "fd_seek", "fd_write"}
	entries, _ := embedded.ReadDir("wasm")
	for _, e := range entries {
		if !strings.HasSuffix(e.Name(), ".wasm") {
			continue
		}
		b, _ := embedded.ReadFile("wasm/" + e.Name())
		c, err := rt.CompileModule(ctx, b)
		if err != nil {
			t.Fatalf("%s: %v", e.Name(), err)
		}
		var got []string
		for _, f := range c.ImportedFunctions() {
			mod, name, _ := f.Import()
			if mod != "wasi_snapshot_preview1" {
				t.Errorf("%s imports %s.%s", e.Name(), mod, name)
			}
			got = append(got, name)
		}
		sort.Strings(got)
		wantHere := want
		if e.Name() == "swift.wasm" {
			wantHere = []string{"clock_time_get", "fd_close", "fd_seek", "fd_write", "proc_exit"}
		}
		if !reflect.DeepEqual(got, wantHere) {
			t.Errorf("%s imports %v, want exactly %v", e.Name(), got, wantHere)
		}
		if len(c.ImportedMemories()) != 0 {
			t.Errorf("%s imports a memory", e.Name())
		}
	}
}

func newParser(t *testing.T) *Parser {
	t.Helper()
	p, err := NewParser(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = p.Close(context.Background()) })
	return p
}

// wellFormed checks the invariants the flat format promises: pre-order,
// parents earlier, every node inside its parent's byte range and the source.
func wellFormed(t *testing.T, tree *Tree, src []byte) {
	t.Helper()
	if len(tree.Nodes) == 0 || tree.Nodes[0].Parent != -1 {
		t.Fatalf("%s: no root", tree.Language)
	}
	for i, n := range tree.Nodes {
		if n.Start > n.End || int(n.End) > len(src) {
			t.Fatalf("%s: node %d %s spans %d..%d of a %d-byte source", tree.Language, i, n.Kind, n.Start, n.End, len(src))
		}
		if i == 0 {
			continue
		}
		p := tree.Nodes[n.Parent]
		if n.Start < p.Start || n.End > p.End {
			t.Fatalf("%s: node %d %s (%d..%d) is outside its parent %s (%d..%d)", tree.Language, i, n.Kind, n.Start, n.End, p.Kind, p.Start, p.End)
		}
	}
}

// find returns the first node of kind whose text is text, or nil.
func find(tree *Tree, src []byte, kind, text string) *Node {
	for i := range tree.Nodes {
		n := &tree.Nodes[i]
		if n.Kind == kind && string(src[n.Start:n.End]) == text {
			return n
		}
	}
	return nil
}

func TestEachLanguageParses(t *testing.T) {
	p := newParser(t)
	for _, c := range []struct {
		lang, src, root string
		// a node whose kind, field and text the tree must hold, and its parent's kind
		kind, field, text, parent string
	}{
		{"python", "def handler(request):\n    q = request.args.get('q')\n    return q\n", "module",
			"identifier", "name", "handler", "function_definition"},
		{"javascript", "app.get('/u', (req, res) => { res.send(req.query.id); });\n", "program",
			"property_identifier", "property", "send", "member_expression"},
		{"typescript", "function load(id: string): Promise<User> { return db.find(id); }\n", "program",
			"identifier", "name", "load", "function_declaration"},
		{"tsx", "export const Card = ({ title }: Props) => <div className=\"card\">{title}</div>;\n", "program",
			"identifier", "name", "Card", "variable_declarator"},
		{"java", "class C { void h(HttpServletRequest request) { String v = request.getParameter(\"v\"); } }\n", "program",
			"identifier", "name", "h", "method_declaration"},
		{"csharp", "class C { void H(HttpRequest r) { var v = r.Query[\"v\"]; } }\n", "compilation_unit",
			"identifier", "name", "H", "method_declaration"},
		{"php", "<?php\nfunction h($r) { $v = $_GET['v']; return $v; }\n", "program",
			"name", "name", "h", "function_definition"},
		{"ruby", "def h(r)\n  v = r.params[:v]\n  v\nend\n", "program",
			"identifier", "name", "h", "method"},
		{"kotlin", "class C {\n  fun h(r: Req): String {\n    val v = r.getParameter(\"v\")\n    return v\n  }\n}\n", "source_file",
			"identifier", "name", "h", "function_declaration"},
		{"scala", "object O {\n  def h(r: Req): String = {\n    val v = r.getParameter(\"v\")\n    v\n  }\n}\n", "compilation_unit",
			"identifier", "name", "h", "function_definition"},
		{"swift", "func h(r: Req) -> String {\n  let v = r.query(\"v\")\n  return v\n}\n", "source_file",
			"simple_identifier", "name", "h", "function_declaration"},
		{"rust", "fn h(r: &Req) -> String {\n    let v = r.query(\"v\");\n    v\n}\n", "source_file",
			"identifier", "name", "h", "function_item"},
	} {
		src := []byte(c.src)
		tree, err := p.Parse(context.Background(), c.lang, src)
		if err != nil {
			t.Fatalf("%s: %v", c.lang, err)
		}
		wellFormed(t, tree, src)
		if tree.Nodes[0].Kind != c.root {
			t.Errorf("%s: root %q, want %q", c.lang, tree.Nodes[0].Kind, c.root)
		}
		if tree.HasError() {
			t.Errorf("%s: a valid source parsed with errors", c.lang)
		}
		n := find(tree, src, c.kind, c.text)
		if n == nil {
			t.Fatalf("%s: no %s %q in the tree", c.lang, c.kind, c.text)
		}
		if n.Field != c.field || !n.Named {
			t.Errorf("%s: %s %q has field %q named=%v, want field %q named", c.lang, c.kind, c.text, n.Field, n.Named, c.field)
		}
		if got := tree.Nodes[n.Parent].Kind; got != c.parent {
			t.Errorf("%s: %s %q is under %s, want %s", c.lang, c.kind, c.text, got, c.parent)
		}
	}
}

func TestBrokenSourceIsFlaggedNotFailed(t *testing.T) {
	p := newParser(t)
	src := []byte("def f(:\n    return )\n")
	tree, err := p.Parse(context.Background(), "python", src)
	if err != nil {
		t.Fatal(err)
	}
	wellFormed(t, tree, src)
	if !tree.HasError() {
		t.Error("a broken source parsed without errors")
	}
}

// Same input, same tree: each parse runs in a fresh instance.
func TestParseIsDeterministic(t *testing.T) {
	p := newParser(t)
	src, err := os.ReadFile("treesitter.go")
	if err != nil {
		t.Fatal(err)
	}
	a, err := p.Parse(context.Background(), "javascript", src) // a Go file read as JS: an error-heavy tree
	if err != nil {
		t.Fatal(err)
	}
	b, err := p.Parse(context.Background(), "javascript", src)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(a, b) {
		t.Error("two parses of the same source differ")
	}
}

func TestUnknownLanguage(t *testing.T) {
	p := newParser(t)
	if _, err := p.Parse(context.Background(), "cobol", []byte("x")); !errors.Is(err, ErrLanguage) {
		t.Errorf("err = %v, want ErrLanguage", err)
	}
}

func TestCancelledContextIsAnError(t *testing.T) {
	p := newParser(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := p.Parse(ctx, "python", []byte("x = 1\n")); err == nil {
		t.Error("a parse under a cancelled context succeeded")
	}
}

func TestEmptySource(t *testing.T) {
	p := newParser(t)
	tree, err := p.Parse(context.Background(), "java", nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(tree.Nodes) != 1 || tree.Nodes[0].Kind != "program" {
		t.Errorf("empty source: %+v", tree.Nodes)
	}
}

// decode checks the guest's array instead of trusting it: a parent that is
// not earlier, a second root, or a symbol outside the language is an error.
func TestDecodeRejectsMalformedRecords(t *testing.T) {
	n := &names{symbols: []string{"end", "module", "identifier"}, fields: []string{"", "name"}}
	rec := func(words ...uint32) []byte {
		b := make([]byte, 0, len(words)*4)
		for _, w := range words {
			b = append(b, byte(w), byte(w>>8), byte(w>>16), byte(w>>24))
		}
		return b
	}
	root := []uint32{1, 0, 0, 3, 0xFFFFFFFF, flagNamed}
	for _, c := range []struct {
		name string
		raw  []byte
		ok   bool
	}{
		{"root and a child", rec(append(append([]uint32{}, root...), 2, 1, 0, 1, 0, flagNamed)...), true},
		{"an ERROR node", rec(append(append([]uint32{}, root...), 0xFFFF, 0, 0, 1, 0, flagError)...), true},
		{"parent not earlier", rec(append(append([]uint32{}, root...), 2, 0, 0, 1, 1, 0)...), false},
		{"a second root", rec(append(append([]uint32{}, root...), 2, 0, 0, 1, 0xFFFFFFFF, 0)...), false},
		{"symbol outside the language", rec(append(append([]uint32{}, root...), 7, 0, 0, 1, 0, 0)...), false},
		{"field outside the language", rec(append(append([]uint32{}, root...), 2, 5, 0, 1, 0, 0)...), false},
	} {
		_, err := decode("python", n, c.raw, 2)
		if (err == nil) != c.ok {
			t.Errorf("%s: err = %v, want ok=%v", c.name, err, c.ok)
		}
	}
}
