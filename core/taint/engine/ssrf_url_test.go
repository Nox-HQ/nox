package engine

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestSSRFNeedsATaintedURL: an HTTP client call is SSRF when its URL is
// tainted, not when a header or body is.
func TestSSRFNeedsATaintedURL(t *testing.T) {
	for _, c := range []struct {
		name, file, src string
		lang            lexctx.Lang
		want            []string
	}{
		{"env key in a header", "a.py", "import os, requests\ndef f(url):\n    headers = {'Authorization': os.environ['KEY']}\n    return requests.get(url, headers=headers)\n", lexctx.LangPython, nil},
		{"getter's env header", "a.py", "import os, requests\ndef h():\n    return {'Authorization': os.environ['KEY']}\ndef f(url):\n    return requests.get(url, headers=h())\n", lexctx.LangPython, nil},
		{"request URL", "a.py", "import requests\nfrom flask import request\ndef f():\n    u = request.args.get('u')\n    return requests.get(u)\n", lexctx.LangPython, []string{"TAINT-006"}},
		{"inline request URL", "a.py", "import requests\nfrom flask import request\ndef f():\n    return requests.get(request.args.get('u'))\n", lexctx.LangPython, []string{"TAINT-006"}},
		{"request body is not the URL", "a.py", "import requests\nfrom flask import request\ndef f():\n    return requests.post('https://api.example.com/x', json=request.get_json())\n", lexctx.LangPython, nil},
		{"fetch URL", "a.js", "function h(req) {\n  const r = fetch(req.query.u);\n}\n", lexctx.LangJavaScript, []string{"TAINT-006"}},
		{"fetch body", "a.js", "function h(req) {\n  const r = fetch('https://api.example.com', { body: req.body.b });\n}\n", lexctx.LangJavaScript, nil},
	} {
		got := ruleIDs(NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(c.file, c.lang, []byte(c.src))))
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}
