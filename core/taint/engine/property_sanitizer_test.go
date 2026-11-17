package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestPropertySanitizers: a catalog sanitizer written as a property access
// (`url.lastPathComponent`, no call parens) clears its class like the call
// form. Every twin reads the same untrusted source; the ones that must fire
// read a property the catalog does NOT declare as a sanitizer.
func TestPropertySanitizers(t *testing.T) {
	swiftWrap := func(body string) string {
		return "func h(_ req: Request) throws {\n let p = req.query[\"path\"] ?? \"\"\n" + body + "}\n"
	}
	tests := []struct {
		name string
		lang lexctx.Lang
		file string
		src  string
		want []string
	}{
		{"swift: optional-chained property in a binding", lexctx.LangSwift, "t.swift",
			swiftWrap(" let name = URL(string: p)?.lastPathComponent ?? \"x\"\n try FileManager.default.removeItem(atPath: \"/srv/data/\" + name)\n"), nil},
		{"swift: bare property on the variable", lexctx.LangSwift, "t.swift",
			swiftWrap(" let name = p.lastPathComponent\n try FileManager.default.removeItem(atPath: \"/srv/data/\" + name)\n"), nil},
		{"swift: property inside the sink argument", lexctx.LangSwift, "t.swift",
			swiftWrap(" try FileManager.default.removeItem(atPath: \"/srv/data/\" + URL(string: p)?.lastPathComponent)\n"), nil},
		{"swift: property of a URL initializer", lexctx.LangSwift, "t.swift",
			swiftWrap(" let name = URL(fileURLWithPath: p).lastPathComponent\n try FileManager.default.removeItem(atPath: name)\n"), nil},
		{"swift: .path is not a sanitizer", lexctx.LangSwift, "t.swift",
			swiftWrap(" let name = URL(fileURLWithPath: p).path\n try FileManager.default.removeItem(atPath: name)\n"), []string{"TAINT-004"}},
		{"swift: .absoluteString is not a sanitizer", lexctx.LangSwift, "t.swift",
			swiftWrap(" let name = URL(string: p)?.absoluteString ?? \"\"\n try FileManager.default.removeItem(atPath: name)\n"), []string{"TAINT-004"}},
		{"swift: .path in the sink argument still fires", lexctx.LangSwift, "t.swift",
			swiftWrap(" try FileManager.default.removeItem(atPath: \"/srv/data/\" + URL(string: p)?.path)\n"), []string{"TAINT-004"}},
		{"swift: property clears only the variable it wraps", lexctx.LangSwift, "t.swift",
			swiftWrap(" let q = req.query[\"other\"] ?? \"\"\n let safe = p.lastPathComponent\n try FileManager.default.removeItem(atPath: q)\n _ = safe\n"), []string{"TAINT-004"}},
		{"objc: message-send property", lexctx.LangObjC, "t.m",
			"void h(void) {\n    NSString *p = getenv(\"P\");\n    NSString *n = [p lastPathComponent];\n    NSString *d = [NSString stringWithContentsOfFile:n];\n}\n", nil},
		{"objc: dot property", lexctx.LangObjC, "t.m",
			"void h(void) {\n    NSString *p = getenv(\"P\");\n    NSString *n = p.lastPathComponent;\n    NSString *d = [NSString stringWithContentsOfFile:n];\n}\n", nil},
		{"objc: unsanitized twin fires", lexctx.LangObjC, "t.m",
			"void h(void) {\n    NSString *p = getenv(\"P\");\n    NSString *n = [p stringByAppendingString:@\"x\"];\n    NSString *d = [NSString stringWithContentsOfFile:n];\n}\n", []string{"TAINT-004"}},
		// A language whose catalog declares no such sanitizer is unaffected.
		{"javascript: lastPathComponent is not a sanitizer there", lexctx.LangJavaScript, "t.js",
			"function h(req) {\n  const p = req.query.p;\n  const n = p.lastPathComponent;\n  fs.readFile(n);\n}\n", []string{"TAINT-004"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(tt.file, tt.lang, []byte(tt.src))))
			if !slices.Equal(got, tt.want) {
				t.Fatalf("flows = %v, want %v", got, tt.want)
			}
		})
	}
}
