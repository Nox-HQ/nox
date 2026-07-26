package ai

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
)

// scanOneAI runs the full ScanArtifacts pipeline over a single in-memory file.
// The sink post-filters live there, not in ScanFile.
func scanOneAI(t *testing.T, name, src string) []findings.Finding {
	t.Helper()
	dir := t.TempDir()
	abs := filepath.Join(dir, name)
	if err := os.WriteFile(abs, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	fs, _, err := NewAnalyzer().ScanArtifacts(context.Background(),
		[]discovery.Artifact{{Path: name, AbsPath: abs, Type: discovery.Source}})
	if err != nil {
		t.Fatal(err)
	}
	return fs.Findings()
}

// TestAI049_SQLStatementIsNotAnEvalSink covers AI-049 ("AI output passed to
// eval/exec function", CWE-95) reporting high severity on textbook
// PARAMETERISED SQL:
//
//	r.db.Exec(`INSERT INTO schedules (id, prompt) VALUES (?, ?)`, 1, "x")
//
// The rule gates on an AI-vocabulary token inside the call arguments, to
// separate a real eval sink from a database call. Here the token `prompt` is a
// COLUMN NAME inside the SQL text, so the gate passes on a statement that
// contains no AI-derived value at all and is placeholder-parameterised — the
// safe form. `database/sql`'s Exec evaluates SQL, not code, so CWE-95 cannot
// apply to it whatever the arguments are.
//
// The guards are the true positives that must survive: a bare AI variable
// passed to eval/exec, and an AI value interpolated into exec'd code.
func TestAI049_SQLStatementIsNotAnEvalSink(t *testing.T) {
	cases := []struct {
		name string
		file string
		src  string
		want bool
	}{
		{
			name: "parameterised INSERT with a column named prompt",
			file: "repo.go",
			src:  "package p\n\nfunc (r *Repo) Save() error {\n\t_, err := r.db.Exec(`INSERT INTO schedules (id, prompt) VALUES (?, ?)`, 1, \"x\")\n\treturn err\n}\n",
			want: false,
		},
		{
			name: "parameterised SELECT with a column named completion",
			file: "repo.py",
			src:  "cur.execute(\"SELECT id, completion FROM runs WHERE id = %s\", (run_id,))\n",
			want: false,
		},
		{
			name: "model output passed straight to eval",
			file: "run.py",
			src:  "eval(llm_output)\n",
			want: true,
		},
		{
			name: "prompt interpolated into exec'd code",
			file: "run.py",
			src:  "exec(f\"result = compute({prompt})\")\n",
			want: true,
		},
		{
			name: "model output executed as a statement, not SQL text",
			file: "run.py",
			src:  "exec(model_output)\n",
			want: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scanOneAI(t, tc.file, tc.src)
			var ids []string
			fired := false
			for i := range got {
				ids = append(ids, got[i].RuleID)
				if got[i].RuleID == "AI-049" {
					fired = true
				}
			}
			if fired != tc.want {
				t.Errorf("AI-049 fired=%v want=%v (all: %s)", fired, tc.want, strings.Join(ids, ","))
			}
		})
	}
}
