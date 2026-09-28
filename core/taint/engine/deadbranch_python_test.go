package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A branch whose condition is a constant either always runs or never runs.
// Each case pairs a dead flow (must be silent) with its live twin (must be
// reported), so pruning can only ever remove code that cannot execute.
func TestConstantBranchesArePruned(t *testing.T) {
	head := "from flask import request\n\ndef h():\n    param = request.args.get('q')\n"
	sink := "    cur = con.cursor()\n    cur.execute(f\"SELECT a FROM t WHERE b = '{bar}'\")\n"
	for name, c := range map[string]struct {
		body string
		want bool
	}{
		"if false: tainted branch is dead":      {"    num = 106\n    bar = 'safe'\n    if 7 * 18 + num > 300:\n        bar = param\n", false},
		"if true: tainted branch is live":       {"    num = 86\n    bar = 'safe'\n    if 7 * 42 - num > 200:\n        bar = param\n", true},
		"else after a taken if is dead":         {"    num = 86\n    if 7 * 42 - num > 200:\n        bar = 'safe'\n    else:\n        bar = param\n", false},
		"else after a dead if is taken":         {"    num = 106\n    if 7 * 18 + num > 300:\n        bar = 'safe'\n    else:\n        bar = param\n", true},
		"ternary picks the constant side":       {"    num = 86\n    bar = 'safe' if 7 * 42 - num > 200 else param\n", false},
		"ternary live side":                     {"    num = 106\n    bar = 'safe' if 7 * 18 + num > 300 else param\n", true},
		"string membership, dead":               {"    t = 'This should never happen'\n    bar = 'safe'\n    if 'should' not in t:\n        bar = param\n", false},
		"string membership, live":               {"    t = 'This should never happen'\n    bar = 'safe'\n    if 'should' in t:\n        bar = param\n", true},
		"match on a constant, dead arm":         {"    possible = 'ABC'\n    guess = possible[1]\n    match guess:\n        case 'A':\n            bar = param\n        case 'B':\n            bar = 'bob'\n        case _:\n            bar = param\n", false},
		"match on a constant, live arm":         {"    possible = 'ABC'\n    guess = possible[0]\n    match guess:\n        case 'A':\n            bar = param\n        case _:\n            bar = 'bob'\n", true},
		"alternatives in a case":                {"    possible = 'ABC'\n    guess = possible[2]\n    match guess:\n        case 'A':\n            bar = 'x'\n        case 'C' | 'D':\n            bar = param\n        case _:\n            bar = 'y'\n", true},
		"unknown condition stays conditional":   {"    bar = 'safe'\n    if param:\n        bar = param\n", true},
		"a name assigned twice is not constant": {"    n = 1\n    n = 500\n    bar = 'safe'\n    if n > 100:\n        bar = param\n", true},
		"a parameter is not constant":           {"    bar = 'safe'\n    if len(param) > 3:\n        bar = param\n", true},
		"a loop variable is not constant":       {"    bar = 'safe'\n    for i in range(3):\n        if i == 2:\n            bar = param\n", true},
		"a comment is not the condition":        {"    num = 86\n    bar = 'safe'\n    if 7 * 42 - num > 200:  # 7 * 18 > 300\n        bar = param\n", true},
	} {
		got := slices.Contains(analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+c.body+sink), "TAINT-001")
		if got != c.want {
			t.Errorf("%s: reported=%v, want %v", name, got, c.want)
		}
	}
}

// A sink in a pruned header's condition still runs.
func TestAConditionIsStillAStatement(t *testing.T) {
	src := "import os\nfrom flask import request\n\ndef h():\n    c = request.args.get('c')\n    if os.system(c):\n        pass\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, src); !slices.Contains(got, "TAINT-002") {
		t.Errorf("a sink in an if condition was lost: %v", got)
	}
}

func TestEvalPyConst(t *testing.T) {
	env := pyConstEnv{"num": {kind: 'i', i: 86}, "s": {kind: 's', s: "ABC"}}
	for expr, want := range map[string]bool{
		"7 * 42 - num > 200":        true,
		"(7 * 18) + num > 300":      false,
		"'B' in s":                  true,
		"'x' not in s":              true,
		"s[1] == 'B'":               true,
		"s[-1] == 'C'":              true,
		"not (num > 1 and num < 5)": true,
	} {
		v, ok := evalPyConst(expr, env)
		if !ok || v.truthy() != want {
			t.Errorf("%q = %+v ok=%v, want %v", expr, v, ok, want)
		}
	}
	for _, expr := range []string{"len(s) > 1", "x > 1", "s.upper() == 'ABC'", "f'{s}' == 'ABC'", "1 < num < 200", "num / 2 > 1", "-7 // 2 == -4"} {
		if _, ok := evalPyConst(expr, env); ok {
			t.Errorf("%q evaluated; it must be refused", expr)
		}
	}
}
