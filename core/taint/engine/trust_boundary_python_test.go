package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestTrustBoundaryPython(t *testing.T) {
	head := "from flask import request, session\nimport flask\n\ndef h():\n    bar = request.form.get('u')\n"
	for name, body := range map[string]string{
		"tainted value":          "    session['user'] = bar\n",
		"tainted key":            "    flask.session[bar] = '12345'\n",
		"django request.session": "    request.session['who'] = bar\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+body); !slices.Contains(got, "TAINT-011") {
			t.Errorf("%s: session store not reported (got %v)", name, got)
		}
	}
	for name, body := range map[string]string{
		"constant stored":     "    session['user'] = 'guest'\n",
		"a session read":      "    x = session['user']\n",
		"a comparison":        "    ok = session['user'] == bar\n",
		"unrelated subscript": "    cache['user'] = bar\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+body); slices.Contains(got, "TAINT-011") {
			t.Errorf("%s: reported (got %v)", name, got)
		}
	}
}
