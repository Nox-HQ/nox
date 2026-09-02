package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A sanitizer wrapping the source in the SAME binding it is assigned from —
// `n = int(request.args.get('n'))` — is the ordinary way to validate input.
// The engine used to see only "this binding reads a source" and taint n with
// nothing cleared, so every such validated value fired at its sink. The
// binding's expression is now scanned the way a sink argument is: the classes
// of a sanitizer on the path from the expression root to the source are
// cleared on the assignee.
func TestBindingSanitizerWrappingSource(t *testing.T) {
	cases := []struct {
		name string
		path string
		lang lexctx.Lang
		src  string
		want []string
	}{
		{
			name: "python int() around the source clears command injection",
			path: "t.py", lang: lexctx.LangPython,
			src:  "import os\nfrom flask import request\ndef f():\n    n = int(request.args.get('n'))\n    os.system('sleep ' + str(n))\n",
			want: nil,
		},
		{
			name: "python raw source still fires",
			path: "t.py", lang: lexctx.LangPython,
			src:  "import os\nfrom flask import request\ndef f():\n    n = request.args.get('n')\n    os.system('sleep ' + n)\n",
			want: []string{"TAINT-002"},
		},
		{
			name: "python a second, unwrapped source in the same binding keeps the taint",
			path: "t.py", lang: lexctx.LangPython,
			src:  "import os\nfrom flask import request\ndef f():\n    n = int(request.args.get('a')) + request.args.get('b')\n    os.system('sleep ' + n)\n",
			want: []string{"TAINT-002"},
		},
		{
			name: "python the sanitizer clears only its own classes",
			path: "t.py", lang: lexctx.LangPython,
			src:  "import os\nfrom flask import request\ndef f():\n    p = html.escape(request.args.get('p'))\n    os.system('cat ' + p)\n",
			want: []string{"TAINT-002"},
		},
		{
			name: "python a sanitizer beside the source, not around it, clears nothing",
			path: "t.py", lang: lexctx.LangPython,
			src:  "import os\nfrom flask import request\ndef f():\n    n = request.args.get('n') + str(int(x))\n    os.system('sleep ' + n)\n",
			want: []string{"TAINT-002"},
		},
		{
			name: "javascript parseInt around the source",
			path: "t.js", lang: lexctx.LangJavaScript,
			src:  "const child_process = require('child_process');\nfunction h(req, res) {\n  const n = parseInt(req.query.n);\n  child_process.execSync('sleep ' + n);\n}\n",
			want: nil,
		},
		{
			name: "java Integer.parseInt around the source",
			path: "T.java", lang: lexctx.LangJava,
			src:  "class A { void f(HttpServletRequest request) throws Exception {\n  int n = Integer.parseInt(request.getParameter(\"n\"));\n  Runtime.getRuntime().exec(\"sleep \" + n);\n}}\n",
			want: nil,
		},
		{
			name: "php intval around the superglobal",
			path: "t.php", lang: lexctx.LangPHP,
			src:  "<?php\n$n = intval($_GET['n']);\nsystem('sleep ' . $n);\n",
			want: nil,
		},
		{
			name: "ruby Integer() around params",
			path: "t.rb", lang: lexctx.LangRuby,
			src:  "def f\n  n = Integer(params[:n])\n  system(\"sleep #{n}\")\nend\n",
			want: nil,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, c.path, c.lang, c.src)
			if strings.Join(got, ",") != strings.Join(c.want, ",") {
				t.Fatalf("got %v, want %v\n%s", got, c.want, c.src)
			}
		})
	}
}
