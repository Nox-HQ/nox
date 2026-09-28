package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestReflectedXSSThroughFlaskReturn(t *testing.T) {
	route := "from flask import Flask, request, make_response, jsonify\nimport html\napp = Flask(__name__)\n\n@app.route('/x', methods=['POST'])\ndef h():\n    bar = request.form.get('q')\n"
	for name, body := range map[string]string{
		"f-string returned":         "    return f'<p>{bar}</p>'\n",
		"accumulated then returned": "    RESPONSE = ''\n    RESPONSE += f'value: {bar}'\n    return RESPONSE\n",
		"make_response body":        "    return make_response(bar)\n",
		"make_response tuple body":  "    return make_response((f'<b>{bar}</b>', 200))\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, route+body); !slices.Contains(got, "TAINT-003") {
			t.Errorf("%s: reflected XSS not reported (got %v)", name, got)
		}
	}
	for name, body := range map[string]string{
		"escaped":             "    return f'<p>{html.escape(bar)}</p>'\n",
		"escaped first":       "    e = html.escape(bar)\n    return f'<p>{e}</p>'\n",
		"jsonify":             "    return jsonify(q=bar)\n",
		"dict is JSON":        "    return {'q': bar}\n",
		"tainted header only": "    r = make_response(('constant body', {'X-Q': bar}))\n    return r\n",
		"constant":            "    return 'ok'\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, route+body); slices.Contains(got, "TAINT-003") {
			t.Errorf("%s: safe response reported (got %v)", name, got)
		}
	}
}

func TestFlaskReturnSinkNeedsARouteAndFlask(t *testing.T) {
	notRoute := "from flask import request\n\ndef helper():\n    bar = request.args.get('q')\n    return f'<p>{bar}</p>'\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, notRoute); slices.Contains(got, "TAINT-003") {
		t.Errorf("a non-route helper's return was reported: %v", got)
	}
	// FastAPI serializes a returned str as JSON.
	fastapi := "from fastapi import FastAPI, Request\napp = FastAPI()\n\n@app.get('/x')\ndef h(request: Request):\n    bar = request.query_params.get('q')\n    return f'<p>{bar}</p>'\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, fastapi); slices.Contains(got, "TAINT-003") {
		t.Errorf("a FastAPI return was reported: %v", got)
	}
}

// `x += y` is an assignment that keeps x's taint and adds y's. It was not an
// assignment at all, so taint carried by it was dropped for every sink.
func TestPythonAugmentedAssignmentCarriesTaint(t *testing.T) {
	head := "from flask import request\n\ndef h():\n    q = request.args.get('q')\n"
	sql := head + "    sql = 'SELECT a FROM t WHERE b = '\n    sql += q\n    cur = con.cursor()\n    cur.execute(sql)\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, sql); !slices.Contains(got, "TAINT-001") {
		t.Errorf("taint through += was dropped (got %v)", got)
	}
	// The target's own taint is kept: appending a constant does not clean it.
	keep := head + "    sql = 'SELECT a FROM t WHERE b = ' + q\n    sql += ' LIMIT 1'\n    cur = con.cursor()\n    cur.execute(sql)\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, keep); !slices.Contains(got, "TAINT-001") {
		t.Errorf("+= of a constant cleaned a tainted target (got %v)", got)
	}
	clean := head + "    sql = 'SELECT a FROM t'\n    sql += ' LIMIT 1'\n    cur = con.cursor()\n    cur.execute(sql)\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, clean); slices.Contains(got, "TAINT-001") {
		t.Errorf("constants joined with += were reported (got %v)", got)
	}
}
