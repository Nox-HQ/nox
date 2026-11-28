package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func continuationRules(path string, lang lexctx.Lang, src string) []string {
	return ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(path, lang, []byte(src))))
}

// A statement split after an operator or an assignment is one statement:
// each case loses its flow on the bracket count alone.
func TestTrailingOperatorContinuesTheStatement(t *testing.T) {
	cases := []struct {
		name, path string
		lang       lexctx.Lang
		src        string
	}{
		{"perl concatenation", "x.pl", lexctx.LangPerl, "sub h {\n  my $c = \"ls \" .\n    $ENV{X};\n  system($c);\n}\n"},
		{"perl initializer", "x.pl", lexctx.LangPerl, "sub h {\n  my $c =\n    $ENV{X};\n  system($c);\n}\n"},
		{"powershell plus", "x.ps1", lexctx.LangPowerShell, "function h {\n  $c = \"ls \" +\n    $args[0]\n  Start-Process $c\n}\n"},
		{"powershell backtick", "x.ps1", lexctx.LangPowerShell, "function h {\n  $c = \"ls \" `\n    + $args[0]\n  Start-Process $c\n}\n"},
		{"objc initializer", "x.m", lexctx.LangObjC, "void h(void) {\n  char *c =\n      getenv(\"X\");\n  system(c);\n}\n"},
		{"lua concatenation", "x.lua", lexctx.LangLua, "function h()\n  local c = \"ls \" ..\n    os.getenv(\"X\")\n  os.execute(c)\nend\n"},
		{"lua initializer", "x.lua", lexctx.LangLua, "function h()\n  local c =\n    os.getenv(\"X\")\n  os.execute(c)\nend\n"},
		{"elixir concatenation", "x.ex", lexctx.LangElixir, "defmodule M do\n  def h(conn) do\n    c = \"ls \" <>\n      conn.params[\"x\"]\n    System.cmd(\"sh\", [\"-c\", c])\n  end\nend\n"},
		{"elixir initializer", "x.ex", lexctx.LangElixir, "defmodule M do\n  def h(conn) do\n    c =\n      conn.params[\"x\"]\n    System.cmd(\"sh\", [\"-c\", c])\n  end\nend\n"},
		{"dart plus", "x.dart", lexctx.LangDart, "Future<Response> h(Request request) async {\n  final body = 'ls ' +\n      await request.readAsString();\n  await Process.run('sh', ['-c', body]);\n  return Response.ok('ok');\n}\n"},
		{"dart initializer", "x.dart", lexctx.LangDart, "Future<Response> h(Request request) async {\n  final body =\n      await request.readAsString();\n  await Process.run('sh', ['-c', body]);\n  return Response.ok('ok');\n}\n"},
		{"groovy plus", "x.groovy", lexctx.LangGroovy, "class C {\n    def m(request) {\n        def cmd = \"ls \" +\n            request.getParameter(\"cmd\")\n        cmd.execute()\n    }\n}\n"},
		{"groovy initializer", "x.groovy", lexctx.LangGroovy, "class C {\n    def m(request) {\n        def cmd =\n            request.getParameter(\"cmd\")\n        cmd.execute()\n    }\n}\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if ids := continuationRules(tt.path, tt.lang, tt.src); !hasID(ids, "TAINT-002") {
				t.Errorf("want TAINT-002; got %v", ids)
			}
		})
	}
}

// Only code counts, and only a whole word operator: joined, each case would
// take the next line's source into c, which reaches the sink only that way.
func TestTrailingOperatorNeedsCode(t *testing.T) {
	cases := []struct {
		name, path string
		lang       lexctx.Lang
		src        string
	}{
		{"operator in a comment", "x.lua", lexctx.LangLua, "function h()\n  local c = \"ls\" -- see x =\n  local d = os.getenv(\"X\")\n  os.execute(c)\nend\n"},
		{"operator in a string", "x.pl", lexctx.LangPerl, "sub h {\n  my $c = \"ls =\";\n  my $d = $ENV{X};\n  system($c);\n}\n"},
		{"identifier ending in or", "x.lua", lexctx.LangLua, "function h()\n  local c = \"ls \" .. color\n  local d = os.getenv(\"X\")\n  os.execute(c)\nend\n"},
		{"identifier ending in and", "x.pl", lexctx.LangPerl, "sub h {\n  my $c = $brand\n  my $d = $ENV{X};\n  system($c);\n}\n"},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if ids := continuationRules(tt.path, tt.lang, tt.src); hasID(ids, "TAINT-002") {
				t.Errorf("want no TAINT-002; got %v", ids)
			}
		})
	}
}

func hasID(ids []string, id string) bool {
	for _, x := range ids {
		if x == id {
			return true
		}
	}
	return false
}
