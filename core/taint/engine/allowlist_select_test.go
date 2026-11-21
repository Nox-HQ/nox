package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A sort column drawn from a literal allowlist is the defence an ORDER BY
// needs, since a column cannot be bound. The safe twins RealVuln's generated
// applications place beside each vulnerable query were reported exactly like
// it. Each "safe" case is one of those shapes; each "kept" case looks like it
// but the value can still be anything the request sent, and stays reported.
func TestAllowlistSelectClearsTheSortColumn(t *testing.T) {
	js := func(decls, sel string) string {
		return decls + "\nasync function h(req) {\n  const sort = req.query.sort;\n  " + sel +
			"\n  return prisma.$queryRawUnsafe(`SELECT * FROM t ORDER BY ${column} DESC`);\n}\n"
	}
	java := func(fields, sel string) string {
		return "package a;\n\npublic class C {\n" + fields +
			"\n    public Object h(HttpServletRequest request) {\n        String sort = request.getParameter(\"sort\");\n        " + sel +
			"\n        return em.createNativeQuery(\"SELECT * FROM t ORDER BY \" + column, T.class).getResultList();\n    }\n}\n"
	}
	py := func(decls, sel string) string {
		return "from flask import request\n" + decls + "\n\ndef h():\n    sort = request.args.get('sort')\n    " + sel +
			"\n    cursor.execute('SELECT * FROM t ORDER BY ' + column)\n"
	}
	for _, c := range []struct {
		name string
		lang lexctx.Lang
		src  string
		want bool
	}{
		// Membership selects over literal collections.
		{"safe: Set.has ternary", lexctx.LangJavaScript,
			js(`const ALLOWED = new Set(["title", "status", "createdAt"]);`, `const column = ALLOWED.has(sort) ? sort : "createdAt";`), false},
		{"safe: multi-line Set", lexctx.LangJavaScript,
			js("const ALLOWED = new Set([\n  \"title\",\n  \"status\",\n]);", `const column = ALLOWED.has(sort) ? sort : "createdAt";`), false},
		{"safe: array includes", lexctx.LangJavaScript,
			js(`const COLUMNS = ['createdAt', 'amount', 'status'];`, `const column = COLUMNS.includes(sort) ? sort : 'createdAt';`), false},
		{"safe: negated", lexctx.LangJavaScript,
			js(`const COLUMNS = ['createdAt', 'amount'];`, `const column = !COLUMNS.includes(sort) ? 'createdAt' : sort;`), false},
		{"safe: inline Set.of", lexctx.LangJava,
			java("", `String column = Set.of("name", "price", "created_at").contains(sort) ? sort : "created_at";`), false},
		{"safe: static Set.of field", lexctx.LangJava,
			java(`    private static final Set<String> SORTS = Set.of("ASC", "DESC");`, `String column = SORTS.contains(sort) ? sort : "ASC";`), false},
		{"safe: python in", lexctx.LangPython,
			py(`ALLOWED = {"title", "status"}`, `column = sort if sort in ALLOWED else "title"`), false},
		{"safe: python frozenset", lexctx.LangPython,
			py(`ALLOWED = frozenset(("title", "status"))`, `column = sort if sort in ALLOWED else "title"`), false},
		// Lookups in literal maps: the key selects, the value is returned.
		{"safe: Map.of getOrDefault", lexctx.LangJava,
			java("    private static final Map<String, String> SORT = Map.of(\n            \"created\", \"created_at\",\n            \"amount\", \"amount\"\n    );",
				`String column = SORT.getOrDefault(sort, "created_at");`), false},
		{"safe: static block puts", lexctx.LangJava,
			java("    private static final Map<String, String> SORT = new HashMap<>();\n    static {\n        SORT.put(\"created\", \"created_at\");\n        SORT.put(\"amount\", \"amount\");\n    }",
				`String column = SORT.getOrDefault(sort, "created_at");`), false},
		{"safe: python dict get", lexctx.LangPython,
			py(`SORT = {"created": "created_at", "amount": "amount"}`, `column = SORT.get(sort, "created_at")`), false},
		{"safe: js object lookup", lexctx.LangJavaScript,
			js(`const SORT = { created: "created_at", amount: "amount" };`, `const column = SORT[sort] ?? "created_at";`), false},

		// Look-alikes that still let the request choose the value.
		{"kept: no allowlist", lexctx.LangJavaScript,
			js("", `const column = sort || "createdAt";`), true},
		{"kept: collection is a parameter", lexctx.LangJavaScript,
			"async function h(req, ALLOWED) {\n  const sort = req.query.sort;\n  const column = ALLOWED.has(sort) ? sort : \"createdAt\";\n  return prisma.$queryRawUnsafe(`SELECT * FROM t ORDER BY ${column}`);\n}\n", true},
		{"kept: collection holds a variable", lexctx.LangJavaScript,
			js(`const ALLOWED = new Set(["title", extra]);`, `const column = ALLOWED.has(sort) ? sort : "createdAt";`), true},
		{"kept: collection is added to", lexctx.LangJavaScript,
			js("const ALLOWED = new Set([\"title\"]);\nALLOWED.add(process.env.EXTRA);", `const column = ALLOWED.has(sort) ? sort : "createdAt";`), true},
		{"kept: collection is rebound", lexctx.LangJavaScript,
			js("let ALLOWED = new Set([\"title\"]);\nALLOWED = loadColumns();", `const column = ALLOWED.has(sort) ? sort : "createdAt";`), true},
		{"kept: checks one value, returns another", lexctx.LangJavaScript,
			js(`const ALLOWED = new Set(["title"]);`, `const column = ALLOWED.has(other) ? sort : "createdAt";`), true},
		{"kept: default is the request value", lexctx.LangJavaScript,
			js(`const ALLOWED = new Set(["title"]);`, `const column = ALLOWED.has(sort) ? sort : req.query.fallback;`), true},
		{"kept: map with a non-literal store", lexctx.LangJava,
			java("    private static final Map<String, String> SORT = new HashMap<>();\n    static {\n        SORT.put(\"created\", System.getenv(\"COL\"));\n    }",
				`String column = SORT.getOrDefault(sort, "created_at");`), true},
		{"kept: python membership in a parameter", lexctx.LangPython,
			"from flask import request\n\ndef h(allowed):\n    sort = request.args.get('sort')\n    column = sort if sort in allowed else 'title'\n    cursor.execute('SELECT * FROM t ORDER BY ' + column)\n", true},
	} {
		got := slices.Contains(analyzeRuleIDs(t, "t"+extFor(c.lang), c.lang, c.src), "TAINT-001")
		if got != c.want {
			t.Errorf("%s: TAINT-001 reported = %v, want %v", c.name, got, c.want)
		}
	}
}

// The select clears the assignee only. The value it was chosen from is still
// what the request sent, and reaches a sink as itself.
func TestAllowlistSelectLeavesTheCheckedValueTainted(t *testing.T) {
	src := "const ALLOWED = new Set([\"title\"]);\nasync function h(req) {\n  const sort = req.query.sort;\n  const column = ALLOWED.has(sort) ? sort : \"title\";\n" +
		"  return prisma.$queryRawUnsafe(`SELECT * FROM t WHERE x = '${sort}' ORDER BY ${column}`);\n}\n"
	if !slices.Contains(analyzeRuleIDs(t, "t.js", lexctx.LangJavaScript, src), "TAINT-001") {
		t.Error("the checked value itself reached the query and was not reported")
	}
}
