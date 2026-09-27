package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// `if not param: param = ""` is the commonest defaulting idiom in Python web
// code, and it made a tainted param clean: the reassignment was treated as if
// it always ran. Every SQL injection case in the OWASP Benchmark for Python
// carries that guard.
func TestAConditionalReassignmentDoesNotCleanAValue(t *testing.T) {
	head := "from flask import request\n\ndef h():\n    param = request.args.get('q')\n"
	sink := "    cur = con.cursor()\n    cur.execute(f\"SELECT a FROM t WHERE p = '{param}'\")\n"
	fires := func(mid string) bool {
		return slices.Contains(analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+mid+sink), "TAINT-001")
	}
	for name, mid := range map[string]string{
		"if not x: x = default": "    if not param:\n        param = ''\n",
		"else branch":           "    if ok():\n        pass\n    else:\n        param = 'x'\n",
		"loop body":             "    for _ in range(3):\n        param = 'x'\n",
		"except branch":         "    try:\n        check()\n    except ValueError:\n        param = 'x'\n",
		"conditional sanitizer": "    if strict():\n        param = int(param)\n",
		"nested conditional":    "    if a():\n        if b():\n            param = ''\n",
	} {
		if !fires(mid) {
			t.Errorf("%s: the value lost its taint", name)
		}
	}
	// Unconditional reassignment still cleans, including after a block closes
	// and inside `with` / `try:` bodies, which always run.
	for name, mid := range map[string]string{
		"plain reassignment":  "    param = ''\n",
		"after an if block":   "    if a():\n        pass\n    param = ''\n",
		"inside with":         "    with lock():\n        param = ''\n",
		"inside try body":     "    try:\n        param = ''\n    except ValueError:\n        pass\n",
		"unconditional int()": "    param = int(param)\n",
	} {
		if fires(mid) {
			t.Errorf("%s: an unconditional clean assignment no longer cleans", name)
		}
	}
}
