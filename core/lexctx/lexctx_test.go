package lexctx

import (
	"testing"
)

func TestLangFromPath(t *testing.T) {
	tests := []struct {
		path string
		want Lang
	}{
		{"a.py", LangPython},
		{"a.pyi", LangPython},
		{"src/App.tsx", LangJavaScript},
		{"bundle.min.js", LangJavaScript},
		{"mod.mjs", LangJavaScript},
		{"types.d.ts", LangJavaScript},
		{"README.md", LangUnknown},
		{"Makefile", LangUnknown},
		{"UPPER.PY", LangPython}, // case-insensitive
	}
	for _, tt := range tests {
		if got := LangFromPath(tt.path); got != tt.want {
			t.Errorf("LangFromPath(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestKindString(t *testing.T) {
	tests := []struct {
		k    Kind
		want string
	}{
		{KindCode, "code"},
		{KindString, "string"},
		{KindComment, "comment"},
	}
	for _, tt := range tests {
		if got := tt.k.String(); got != tt.want {
			t.Errorf("Kind(%d).String() = %q, want %q", tt.k, got, tt.want)
		}
	}
}

// regionsCover asserts the region list is contiguous, gap-free, and covers
// exactly [0, total). It is the structural invariant every scanner must uphold.
func regionsCover(t *testing.T, regions []Region, total int) {
	t.Helper()
	if total == 0 {
		if len(regions) != 0 {
			t.Fatalf("empty input should yield no regions, got %d", len(regions))
		}
		return
	}
	if len(regions) == 0 {
		t.Fatalf("non-empty input yielded no regions")
	}
	if regions[0].Start != 0 {
		t.Errorf("first region starts at %d, want 0", regions[0].Start)
	}
	if last := regions[len(regions)-1].End; last != total {
		t.Errorf("last region ends at %d, want %d", last, total)
	}
	for i := 1; i < len(regions); i++ {
		if regions[i].Start != regions[i-1].End {
			t.Errorf("gap/overlap between region %d (end %d) and %d (start %d)",
				i-1, regions[i-1].End, i, regions[i].Start)
		}
		if regions[i].Kind == regions[i-1].Kind {
			t.Errorf("adjacent regions %d and %d share kind %v (not coalesced)",
				i-1, i, regions[i].Kind)
		}
	}
}

func TestClassifyUnknownIsAllCode(t *testing.T) {
	content := []byte("anything at all # not a comment here")
	regions := Classify(LangUnknown, content)
	regionsCover(t, regions, len(content))
	if len(regions) != 1 || regions[0].Kind != KindCode {
		t.Fatalf("unknown language must be one code region, got %+v", regions)
	}
}

func TestClassifyEmpty(t *testing.T) {
	if r := Classify(LangPython, nil); r != nil {
		t.Errorf("empty content should return nil, got %+v", r)
	}
}

func kindOfSubstring(t *testing.T, lang Lang, content, needle string) Kind {
	t.Helper()
	idx := indexOf(content, needle)
	if idx < 0 {
		t.Fatalf("needle %q not found in content", needle)
	}
	regions := Classify(lang, []byte(content))
	regionsCover(t, regions, len(content))
	start, end := idx, idx+len(needle)
	k := KindAt(regions, start)
	// The whole needle should share one kind for these fixtures.
	if !allSameKind(regions, start, end, k) {
		t.Fatalf("needle %q spans multiple kinds", needle)
	}
	return k
}

func allSameKind(regions []Region, start, end int, k Kind) bool {
	for i := start; i < end; i++ {
		if KindAt(regions, i) != k {
			return false
		}
	}
	return true
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// nthIndexOf returns the byte offset of the n-th (0-based) occurrence of needle
// in haystack, or -1 if there are fewer than n+1 occurrences.
func nthIndexOf(haystack, needle string, n int) int {
	start := 0
	for {
		idx := indexOf(haystack[start:], needle)
		if idx < 0 {
			return -1
		}
		if n == 0 {
			return start + idx
		}
		n--
		start += idx + 1
	}
}

func TestScanPython(t *testing.T) {
	src := `API_KEY = "s3cr3t_value_here"
# comment with s3cr3t_value_here inside
doc = """
triple s3cr3t_value_here blob
"""
x = 'single s3cr3t_value_here'
`
	if k := kindOfSubstring(t, LangPython, src, `API_KEY`); k != KindCode {
		t.Errorf("API_KEY should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `"s3cr3t_value_here"`); k != KindString {
		t.Errorf("double-quoted literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `comment with`); k != KindComment {
		t.Errorf("comment body should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `triple s3cr3t_value_here blob`); k != KindString {
		t.Errorf("triple-quoted body should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangPython, src, `'single s3cr3t_value_here'`); k != KindString {
		t.Errorf("single-quoted literal should be string, got %v", k)
	}
}

func TestScanJavaScript(t *testing.T) {
	src := "const apiKey = \"s3cr3t\";\n" +
		"// line comment s3cr3t\n" +
		"/* block s3cr3t comment */\n" +
		"const t = `template s3cr3t line`;\n" +
		"const s = 'single s3cr3t';\n"
	if k := kindOfSubstring(t, LangJavaScript, src, `apiKey`); k != KindCode {
		t.Errorf("apiKey should be code, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `"s3cr3t"`); k != KindString {
		t.Errorf("double-quoted literal should be string, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `line comment s3cr3t`); k != KindComment {
		t.Errorf("line comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, `block s3cr3t comment`); k != KindComment {
		t.Errorf("block comment should be comment, got %v", k)
	}
	if k := kindOfSubstring(t, LangJavaScript, src, "`template s3cr3t line`"); k != KindString {
		t.Errorf("template literal should be string, got %v", k)
	}
}

func TestScanPythonEscapesDoNotEndString(t *testing.T) {
	// A backslash-escaped quote must not close the string early, otherwise the
	// trailing code bytes would be mislabeled.
	src := `x = "a\"b" ; SECRET = 1`
	regions := Classify(LangPython, []byte(src))
	regionsCover(t, regions, len(src))
	if k := kindOfSubstring(t, LangPython, src, `SECRET`); k != KindCode {
		t.Errorf("code after escaped-quote string should be code, got %v", k)
	}
}

func TestKindAtOutOfRange(t *testing.T) {
	regions := Classify(LangPython, []byte(`x = 1`))
	if k := KindAt(regions, 999); k != KindCode {
		t.Errorf("out-of-range offset should default to code, got %v", k)
	}
	if k := KindAt(regions, -5); k != KindCode {
		t.Errorf("negative offset should default to code, got %v", k)
	}
}

func TestInCode(t *testing.T) {
	// code|string|code layout: `a = "xx" + b`
	src := `a = "xx" + b`
	regions := Classify(LangPython, []byte(src))
	tests := []struct {
		name       string
		start, end int
		want       bool
	}{
		{"whole assignment target is code", 0, 3, true},
		{"inside the string literal", 5, 7, false},
		{"spanning code into string is not code", 3, 6, false},
		{"empty span is not code", 4, 4, false},
		{"inverted span is not code", 6, 4, false},
		{"trailing code is code", 9, 12, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := InCode(regions, tt.start, tt.end); got != tt.want {
				t.Errorf("InCode(%d,%d) = %v, want %v", tt.start, tt.end, got, tt.want)
			}
		})
	}
}

func TestSuppressNonCodeUnknownNeverSuppresses(t *testing.T) {
	content := []byte(`# whatever "looks" like a string`)
	if SuppressNonCode(LangUnknown, content, 2, 10) {
		t.Error("unknown language must never suppress (graceful degrade)")
	}
}

// TestSuppressNonCodeStringPolicy pins the crucial secrets-safety behavior: a
// short string literal (a real hardcoded secret) is kept, while a comment and a
// data-blob string are dropped.
func TestSuppressNonCodeStringPolicy(t *testing.T) {
	shortSecret := []byte(`key = "AKIA1234567890ABCDEF1234567890AB"`)
	// Offset of the token inside the short literal.
	i := indexOf(string(shortSecret), "AKIA1234567890ABCDEF1234567890AB")
	if SuppressNonCode(LangPython, shortSecret, i, i+32) {
		t.Error("short hardcoded secret in a string literal must NOT be suppressed")
	}

	dataURI := []byte(`icon = "data:image/svg+xml;base64,AKIA1234567890ABCDEF1234567890AB=="`)
	j := indexOf(string(dataURI), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangPython, dataURI, j, j+32) {
		t.Error("token inside a data-URI blob string must be suppressed")
	}

	comment := []byte("x = 1  # AKIA1234567890ABCDEF1234567890AB legacy")
	k := indexOf(string(comment), "AKIA1234567890ABCDEF1234567890AB")
	if !SuppressNonCode(LangPython, comment, k, k+32) {
		t.Error("token inside a comment must be suppressed")
	}
}
