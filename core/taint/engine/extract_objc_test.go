package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestExtractObjCMessageSendCall pins the core Objective-C shape: a bracket
// message send `[db executeQuery:sql]` is rewritten to the dotted call
// `db.executeQuery(sql)` so the recognizer records the callee suffix
// `executeQuery` and the argument read `sql`.
func TestExtractObjCMessageSendCall(t *testing.T) {
	src := []byte(`void run(void) {
    NSString *sql = getenv("Q");
    [db executeQuery:sql];
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "run")
	st := stmtWithCall(t, u, "db.executeQuery")
	if !containsStr(st.reads, "sql") {
		t.Errorf("reads = %v, want to include sql", st.reads)
	}
}

// TestExtractObjCMultiKeywordSelector: a multi-keyword selector
// `[v loadHTMLString:html baseURL:base]` folds to the first-keyword callee
// `v.loadHTMLString` with both arguments positional.
func TestExtractObjCMultiKeywordSelector(t *testing.T) {
	src := []byte(`void show(void) {
    NSString *html = getenv("H");
    [webView loadHTMLString:html baseURL:base];
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "show")
	st := stmtWithCall(t, u, "webView.loadHTMLString")
	if !containsStr(st.reads, "html") {
		t.Errorf("reads = %v, want to include html (first positional arg)", st.reads)
	}
}

// TestExtractObjCNestedMessageSend: `[[NSString alloc] initWithFormat:cmd]` —
// nested sends fold innermost-first, so the outer callee suffix `initWithFormat`
// is recorded and reads the tainted `cmd`.
func TestExtractObjCNestedMessageSend(t *testing.T) {
	src := []byte(`void f(void) {
    char *cmd = getenv("C");
    NSString *s = [[NSString alloc] initWithFormat:cmd];
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "f")
	st := stmtWithCall(t, u, "initWithFormat")
	if st.assigns != "s" {
		t.Errorf("assign LHS = %q, want s", st.assigns)
	}
	if !containsStr(st.reads, "cmd") {
		t.Errorf("reads = %v, want to include cmd", st.reads)
	}
}

// TestExtractObjCNoArgSelector: a no-argument send `[task launch]` folds to
// `task.launch()` — recorded as a call with the suffix `launch`.
func TestExtractObjCNoArgSelector(t *testing.T) {
	src := []byte(`void f(void) {
    [task launch];
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "f")
	stmtWithCall(t, u, "task.launch")
}

// TestExtractObjCClassMethodSend: a class-method send
// `[NSString stringWithContentsOfFile:path]` folds to
// `NSString.stringWithContentsOfFile(path)`.
func TestExtractObjCClassMethodSend(t *testing.T) {
	src := []byte(`void f(void) {
    NSString *path = getenv("P");
    NSString *data = [NSString stringWithContentsOfFile:path];
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "f")
	st := stmtWithCall(t, u, "NSString.stringWithContentsOfFile")
	if st.assigns != "data" {
		t.Errorf("assign LHS = %q, want data", st.assigns)
	}
	if !containsStr(st.reads, "path") {
		t.Errorf("reads = %v, want to include path", st.reads)
	}
}

// TestExtractObjCMethodHeaderParams: an ObjC method definition
// `- (void)runWith:(NSString *)cmd andArg:(int)n` opens a unit named by the FIRST
// selector keyword `runWith` whose params are the binding names in order.
func TestExtractObjCMethodHeaderParams(t *testing.T) {
	src := []byte(`- (void)runWith:(NSString *)cmd andArg:(int)n {
    NSString *x = cmd;
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "runWith")
	if len(u.params) != 2 || u.params[0] != "cmd" || u.params[1] != "n" {
		t.Fatalf("params = %v, want [cmd n]", u.params)
	}
}

// TestExtractObjCNoArgMethodHeader: `- (NSString *)describe` opens a unit named
// `describe` with no parameters.
func TestExtractObjCNoArgMethodHeader(t *testing.T) {
	src := []byte(`- (NSString *)describe {
    return @"x";
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "describe")
	if len(u.params) != 0 {
		t.Errorf("params = %v, want none", u.params)
	}
}

// TestExtractObjCMethodHeaderNotACall guards that a method header is NOT read as
// a data-flow call to the selector keyword.
func TestExtractObjCMethodHeaderNotACall(t *testing.T) {
	src := []byte(`- (void)handleURL:(NSString *)url {
    NSString *x = url;
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "handleURL")
	for i := range u.stmts {
		if containsStr(u.stmts[i].calls, "handleURL") {
			t.Errorf("method header must not be read as a call to handleURL: %+v", u.stmts[i])
		}
	}
}

// TestExtractObjCCFunctionDef: a plain C function `int helper(char *a)` still
// opens a unit (Objective-C files embed C).
func TestExtractObjCCFunctionDef(t *testing.T) {
	src := []byte(`int helper(char *a, int b) {
    system(a);
    return 0;
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "helper")
	if len(u.params) != 2 || u.params[0] != "a" || u.params[1] != "b" {
		t.Fatalf("params = %v, want [a b]", u.params)
	}
	stmtWithCall(t, u, "system")
}

// TestExtractObjCNSStringDeclAssignment: `NSString *lhs = rhs` strips the type +
// pointer sigil so the bare LHS name is bound (reuses the C/C++ decl-type
// stripping via langCPP).
func TestExtractObjCNSStringDeclAssignment(t *testing.T) {
	src := []byte(`void f(void) {
    NSString *name = getenv("NAME");
    system(name);
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "f")
	src0 := stmtWithCall(t, u, "getenv")
	if src0.assigns != "name" {
		t.Errorf("assign LHS = %q, want name (type + `*` stripped)", src0.assigns)
	}
	sink := stmtWithCall(t, u, "system")
	if !containsStr(sink.reads, "name") {
		t.Errorf("sink reads = %v, want to include name", sink.reads)
	}
}

// TestExtractObjCReturnMessageSend: `return [NSString stringWithContentsOfFile:p]`
// records the returned read `p` and the folded call while still being a return.
func TestExtractObjCReturnMessageSend(t *testing.T) {
	src := []byte(`- (NSString *)load:(NSString *)p {
    return [NSString stringWithContentsOfFile:p];
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "load")
	st := stmtWithCall(t, u, "NSString.stringWithContentsOfFile")
	if !containsStr(st.returns, "p") {
		t.Errorf("returns = %v, want to include p", st.returns)
	}
	if !containsStr(st.reads, "p") {
		t.Errorf("reads = %v, want to include p", st.reads)
	}
}

// TestExtractObjCArrayLiteralNotASend: an `@[...]` array literal is NOT a message
// send — its inner variable is a plain read, and no bogus callee is fabricated.
func TestExtractObjCArrayLiteralNotASend(t *testing.T) {
	src := []byte(`void f(void) {
    NSArray *a = @[userId, other];
}
`)
	units := extractUnits(lexctx.LangObjC, src)
	u := findUnit(t, units, "f")
	// The assignment is recognized and reads the inner identifiers, but there must
	// be no fabricated dotted call from the array literal.
	for i := range u.stmts {
		for _, c := range u.stmts[i].calls {
			if c == "userId" || c == "other" {
				t.Errorf("array literal element must not be read as a call: %q", c)
			}
		}
	}
}
