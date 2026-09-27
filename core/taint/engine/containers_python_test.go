package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A value stored into a Python container and read back out was untainted:
// `m['k'] = param; bar = m['k']`, `l.append(param)`, `conf.set(s, k, param)`.
// Perl and Dart already model element stores and mutator calls as taint on the
// whole container; Python did not, and the OWASP Benchmark for Python routes
// many of its injection cases through exactly these stores.
func TestAValueStoredInAPythonContainerStaysTainted(t *testing.T) {
	head := "from flask import request\nimport configparser\n\ndef h():\n    param = request.args.get('q')\n"
	tail := "    cur = con.cursor()\n    cur.execute(f\"SELECT a FROM t WHERE p = '{bar}'\")\n"
	for name, mid := range map[string]string{
		"dict store":   "    m = {}\n    m['k'] = param\n    bar = m['k']\n",
		"list append":  "    l = []\n    l.append(param)\n    bar = l[0]\n",
		"configparser": "    conf = configparser.ConfigParser()\n    conf.add_section('s')\n    conf.set('s', 'k', param)\n    bar = conf.get('s', 'k')\n",
		"set add":      "    s = set()\n    s.add(param)\n    bar = s.pop()\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+mid+tail); !slices.Contains(got, "TAINT-001") {
			t.Errorf("%s: the stored value lost its taint (got %v)", name, got)
		}
	}

	// A container that only ever holds constants stays clean.
	clean := head + "    m = {}\n    m['k'] = 'constant'\n    bar = m['k']\n" + tail
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, clean); slices.Contains(got, "TAINT-001") {
		t.Errorf("a container of constants was reported: %v", got)
	}
}
