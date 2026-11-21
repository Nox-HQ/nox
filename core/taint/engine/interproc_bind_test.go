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
