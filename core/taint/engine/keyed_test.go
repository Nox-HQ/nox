package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestKeyedContainersPython(t *testing.T) {
	head := "from flask import request\nimport configparser\n\ndef h():\n    param = request.args.get('q')\n"
	sink := "    cur = con.cursor()\n    cur.execute(f\"SELECT a FROM t WHERE b = '{bar}'\")\n"
	cases := []struct {
		name, body string
		want       bool
	}{
		{"dict: the safe key is read", "    m = {}\n    m['keyA'] = 'a'\n    m['keyB'] = param\n    bar = m['keyA']\n", false},
		{"dict: the tainted key is read", "    m = {}\n    m['keyA'] = 'a'\n    m['keyB'] = param\n    bar = m['keyB']\n", true},
		{"dict.get on the tainted key", "    m = {}\n    m['keyB'] = param\n    bar = m.get('keyB')\n", true},
		{"configparser: safe key", "    c = configparser.ConfigParser()\n    c.add_section('s')\n    c.set('s', 'keyA', 'a')\n    c.set('s', 'keyB', param)\n    bar = c.get('s', 'keyA')\n", false},
		{"configparser: tainted key", "    c = configparser.ConfigParser()\n    c.add_section('s')\n    c.set('s', 'keyB', param)\n    bar = c.get('s', 'keyB')\n", true},
		// Anything the rewrite cannot account for keeps whole-container taint.
		{"non-literal key read", "    m = {}\n    m['keyB'] = param\n    k = 'keyA'\n    bar = m[k]\n", true},
		{"container passed whole", "    m = {}\n    m['keyB'] = param\n    use(m)\n    bar = m['keyA']\n", true},
		{"non-empty initializer", "    m = {'keyB': param}\n    bar = m['keyA']\n", true},
		{"update()", "    m = {}\n    m.update(x=param)\n    bar = m['keyA']\n", true},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+c.body+sink), "TAINT-001"); got != c.want {
			t.Errorf("%s: reported=%v, want %v", c.name, got, c.want)
		}
	}
}

func TestKeyedContainersJava(t *testing.T) {
	head := "class A {\n  void doPost(HttpServletRequest request) throws Exception {\n    String param = request.getParameter(\"q\");\n"
	sink := "    Runtime.getRuntime().exec(bar);\n  }\n}\n"
	cases := []struct {
		name, body string
		want       bool
	}{
		{"safe key", "    java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n    map.put(\"keyA\", \"a\");\n    map.put(\"keyB\", param);\n    String bar = (String) map.get(\"keyA\");\n", false},
		{"tainted key", "    java.util.HashMap<String, Object> map = new java.util.HashMap<String, Object>();\n    map.put(\"keyA\", \"a\");\n    map.put(\"keyB\", param);\n    String bar = (String) map.get(\"keyB\");\n", true},
		{"map passed whole", "    java.util.Map<String, Object> map = new java.util.HashMap<>();\n    map.put(\"keyB\", param);\n    use(map);\n    String bar = (String) map.get(\"keyA\");\n", true},
		{"non-literal key", "    java.util.Map<String, Object> map = new java.util.HashMap<>();\n    map.put(\"keyB\", param);\n    String bar = (String) map.get(k);\n", true},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+c.body+sink), "TAINT-002"); got != c.want {
			t.Errorf("%s: reported=%v, want %v", c.name, got, c.want)
		}
	}
}
