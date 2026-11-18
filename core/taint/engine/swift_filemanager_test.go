package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func analyzeSwiftFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	return ruleIDs(eng.AnalyzeFile(ExtractUnits("t.swift", lexctx.LangSwift, []byte(src))))
}

// TestSwiftFileManagerPathSinks: each FileManager call that takes a path (or a
// URL built from one) is a path-traversal sink. Every safe twin reads the same
// untrusted source and is clean only because of the guard (Int coercion)
// or a literal path, so none of them passes for lack of a source.
func TestSwiftFileManagerPathSinks(t *testing.T) {
	wrap := func(body string) string {
		return "func h(_ req: Request) throws {\n let p = req.query[\"path\"] ?? \"\"\n" + body + "}\n"
	}
	tests := []struct {
		name string
		src  string
		want []string
	}{
		{"contents(atPath:)", wrap(" let d = FileManager.default.contents(atPath: p)\n"), []string{"TAINT-004"}},
		{"createFile(atPath:)", wrap(" FileManager.default.createFile(atPath: p, contents: nil)\n"), []string{"TAINT-004"}},
		{"removeItem(atPath:)", wrap(" try FileManager.default.removeItem(atPath: p)\n"), []string{"TAINT-004"}},
		{"copyItem(atPath:toPath:)", wrap(" try FileManager.default.copyItem(atPath: p, toPath: \"/tmp/o\")\n"), []string{"TAINT-004"}},
		{"moveItem(atPath:toPath:)", wrap(" try FileManager.default.moveItem(atPath: p, toPath: \"/tmp/o\")\n"), []string{"TAINT-004"}},
		{"contentsOfDirectory(atPath:)", wrap(" let l = try FileManager.default.contentsOfDirectory(atPath: p)\n"), []string{"TAINT-004"}},
		{"receiver variable", wrap(" let fm = FileManager.default\n try fm.removeItem(atPath: p)\n"), []string{"TAINT-004"}},
		{"removeItem(at: URL(fileURLWithPath:))", wrap(" let u = URL(fileURLWithPath: p)\n try FileManager.default.removeItem(at: u)\n"), []string{"TAINT-004"}},
		{"copyItem(at:to:) inline URL", wrap(" try FileManager.default.copyItem(at: URL(fileURLWithPath: p), to: URL(fileURLWithPath: \"/tmp/o\"))\n"), []string{"TAINT-004"}},
		{"contentsOfDirectory(at:)", wrap(" let u = URL(fileURLWithPath: p)\n let l = try FileManager.default.contentsOfDirectory(at: u, includingPropertiesForKeys: nil)\n"), []string{"TAINT-004"}},

		{"literal path", wrap(" try FileManager.default.removeItem(atPath: \"/srv/data/fixed\")\n"), nil},
		{"Int coercion guard", wrap(" let n = Int(p) ?? 0\n try FileManager.default.removeItem(atPath: \"/srv/data/\\(n)\")\n"), nil},
		{"literal URL", wrap(" try FileManager.default.removeItem(at: URL(fileURLWithPath: \"/srv/data/fixed\"))\n"), nil},
		{"tainted contents only, literal path", wrap(" FileManager.default.createFile(atPath: \"/srv/data/fixed\", contents: p.data(using: .utf8))\n"), nil},
		{"unrelated at: label", wrap(" let x = items.insert(p, at: 0)\n"), nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := analyzeSwiftFile(t, tt.src); !slices.Equal(got, tt.want) {
				t.Fatalf("flows = %v, want %v", got, tt.want)
			}
		})
	}
}
