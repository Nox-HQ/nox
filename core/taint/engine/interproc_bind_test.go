package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A helper that binds its argument to a local before the sink had no summary:
// the summary pass kept a flow only when the variable read AT the sink was the
// parameter, so a caller's source reached nothing. Every class, not only SQL.
func TestAHelperThatBindsItsArgumentFirstIsSummarized(t *testing.T) {
	src := "import os\nfrom flask import request\n\n" +
		"def find(cursor, name):\n    q = \"SELECT * FROM users WHERE name = '%s'\" % name\n    cursor.execute(q)\n\n" +
		"def run(cmd):\n    full = \"ls \" + cmd\n    os.system(full)\n\n" +
		"def h():\n    run(request.args.get('d'))\n    return find(cursor, request.args.get('name'))\n"
	flows := analyzeFile(t, lexctx.LangPython, src)
	for _, fn := range []string{"find", "run"} {
		if !flowWithIntermediate(flows, fn) {
			t.Errorf("no flow from the caller's source through %s: %+v", fn, flows)
		}
	}
}

// What a summary does not hand to a caller: a value bound through a call that
// is not the argument handed on. The forward pass keeps it tainted, which is
// conservative inside a function; summarized, it reported a database row
// written as JSON as the request text it was filtered by (chronos, a Go SSE
// handler), and an argv list run without a shell as a shell command (certbot).
func TestASummaryDoesNotHandOnACallsResult(t *testing.T) {
	for name, src := range map[string]string{
		"query result": "from flask import request\n\n" +
			"def render(pattern):\n    rows = repo.list(pattern)\n    return render_template_string(rows)\n\n" +
			"def h():\n    return render(request.args.get('p'))\n",
		"argv from split": "import subprocess\nfrom flask import request\n\n" +
			"def run(version):\n    cmd = f\"gh release view v{version}\".split()\n    subprocess.run(cmd)\n\n" +
			"def h():\n    run(request.args.get('v'))\n",
	} {
		flows := analyzeFile(t, lexctx.LangPython, src)
		for _, fn := range []string{"render", "run"} {
			if flowWithIntermediate(flows, fn) {
				t.Errorf("%s: a call's result was summarized as the argument: %+v", name, flows)
			}
		}
	}
	// A string operation hands its argument on.
	src := "import os\nfrom flask import request\n\n" +
		"def run(cmd):\n    full = \"ls {}\".format(cmd.strip())\n    os.system(full)\n\n" +
		"def h():\n    run(request.args.get('d'))\n"
	if !flowWithIntermediate(analyzeFile(t, lexctx.LangPython, src), "run") {
		t.Errorf("format and strip did not hand the argument on")
	}
}
