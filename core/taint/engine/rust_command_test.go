package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

func rustFlows(t *testing.T, src string) []taint.Flow {
	t.Helper()
	eng := NewStructuralEngine(nil)
	return eng.AnalyzeFile(ExtractUnits("t.rs", lexctx.LangRust, []byte(src)))
}

// The issue's program (#1106): a CLI with no request input. Nothing here is
// an HTTP source, and `Command::new("git")` is not a tainted executable.
func TestRust1106_FilesystemPathIsNotAnHTTPSource(t *testing.T) {
	src := `use std::path::Path;
use std::process::Command;

fn status(root: &Path) -> std::io::Result<std::process::Output> {
    Command::new("git").arg("-C").arg(root).args(["status", "--short"]).output()
}

fn main() {
    let root = std::env::current_dir().unwrap();
    let _ = status(&root).unwrap();
}
`
	for _, f := range rustFlows(t, src) {
		t.Errorf("unexpected flow: %s %s via %s from %s", f.Sink.RuleID, f.Sink.Call, f.SourceVar, f.Source.Kind)
	}
}

func TestRustCommandClasses(t *testing.T) {
	handler := func(body string) string {
		return "use axum::extract::Query;\nuse std::process::Command;\n\n" +
			"fn run(Query(user): Query<Params>) {\n" + body + "\n}\n"
	}
	cases := []struct {
		name     string
		src      string
		wantRule string // "" = no flow
		wantCWE  string
	}{
		{"tainted executable", handler(`    Command::new(user).output();`), "TAINT-002", "CWE-78"},
		{"shell -c chain", handler(`    Command::new("sh").arg("-c").arg(user).output();`), "TAINT-002", "CWE-78"},
		{"shell -c args vector", handler(`    Command::new("bash").args(["-c", user]).output();`), "TAINT-002", "CWE-78"},
		{"shell by absolute path", handler(`    Command::new("/bin/sh").arg("-c").arg(user).output();`), "TAINT-002", "CWE-78"},
		{"shell held in a binding", handler("    let mut c = Command::new(\"sh\");\n    c.arg(\"-c\");\n    c.arg(user);\n    c.output();"), "TAINT-002", "CWE-78"},
		{"literal program, no separator", handler(`    Command::new("git").arg(user).output();`), "TAINT-012", "CWE-88"},
		{"literal program, args vector", handler(`    Command::new("git").args(["log", user]).output();`), "TAINT-012", "CWE-88"},
		{"binding, no separator", handler("    let mut c = Command::new(\"git\");\n    c.arg(user);\n    c.output();"), "TAINT-012", "CWE-88"},
		{"separator after the value", handler(`    Command::new("git").arg(user).arg("--").output();`), "TAINT-012", "CWE-88"},
		{"separator first", handler(`    Command::new("git").arg("--").arg(user).output();`), "", ""},
		{"separator in the args vector", handler(`    Command::new("git").args(["log", "--", user]).output();`), "", ""},
		{"separator in a binding", handler("    let mut c = Command::new(\"git\");\n    c.arg(\"--\");\n    c.arg(user);\n    c.output();"), "", ""},
		{"value before the separator in the vector", handler(`    Command::new("git").args([user, "--", "x"]).output();`), "TAINT-012", "CWE-88"},
		{"shell is not rescued by a separator", handler(`    Command::new("sh").arg("--").arg("-c").arg(user).output();`), "TAINT-002", "CWE-78"},
		{"shell, builder written one call per line", handler("    Command::new(\"sh\")\n        .arg(\"-c\") // run it\n        .arg(user)\n        .output();"), "TAINT-002", "CWE-78"},
		{"git, builder written one call per line", handler("    Command::new(\"git\")\n        .arg(\"log\")\n        .arg(user)\n        .output();"), "TAINT-012", "CWE-88"},
		{"git with separator, one call per line", handler("    Command::new(\"git\")\n        .arg(\"log\")\n        .arg(\"--\")\n        .arg(user)\n        .output();"), "", ""},
		{"literals only", handler(`    Command::new("git").arg("-C").arg(".").output();`), "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flows := rustFlows(t, c.src)
			if c.wantRule == "" {
				for _, f := range flows {
					t.Errorf("unexpected flow %s via %s (%s)", f.Sink.RuleID, f.SourceVar, f.Sink.Call)
				}
				return
			}
			if len(flows) == 0 {
				t.Fatalf("no flow, want %s", c.wantRule)
			}
			for _, f := range flows {
				if f.Sink.RuleID != c.wantRule || f.Sink.CWE != c.wantCWE {
					t.Errorf("flow %s %s via %s, want %s %s", f.Sink.RuleID, f.Sink.CWE, f.SourceVar, c.wantRule, c.wantCWE)
				}
				if f.Source.Kind != taint.SourceHTTPQuery {
					t.Errorf("source kind %s, want http_query for a Query extractor", f.Source.Kind)
				}
			}
		})
	}
}

// Local-operator inputs reach the same sinks as in Python (`sys.argv`) and Go
// (`os.Args`): labelled argv/env, not http_*.
func TestRustArgvAndEnvKeepTheirOrigin(t *testing.T) {
	cases := []struct {
		name string
		body string
		kind taint.SourceKind
		rule string
	}{
		{"argv to executable", "    let p = std::env::args().nth(1).unwrap();\n    Command::new(p).output();", taint.SourceArgv, "TAINT-002"},
		{"env to executable", "    let p = std::env::var(\"TOOL\").unwrap();\n    Command::new(p).output();", taint.SourceEnv, "TAINT-002"},
		{"argv to a shell -c", "    let p = std::env::args().nth(1).unwrap();\n    Command::new(\"sh\").arg(\"-c\").arg(p).output();", taint.SourceArgv, "TAINT-002"},
		{"argv to git, no separator", "    let p = std::env::args().nth(1).unwrap();\n    Command::new(\"git\").arg(p).output();", taint.SourceArgv, "TAINT-012"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			flows := rustFlows(t, "use std::process::Command;\nfn main() {\n"+c.body+"\n}\n")
			if len(flows) == 0 {
				t.Fatalf("no flow")
			}
			for _, f := range flows {
				if f.Source.Kind != c.kind || f.Sink.RuleID != c.rule {
					t.Errorf("got %s from %s, want %s from %s", f.Sink.RuleID, f.Source.Kind, c.rule, c.kind)
				}
			}
		})
	}
}

// A parameter typed with a bare `Path` is a filesystem path; only a generic
// extractor is a request value.
func TestRustExtractorSeedNeedsATypeArgument(t *testing.T) {
	for _, hdr := range []string{"root: &Path", "root: &std::path::Path", "root: Path", "root: &PathBuf", "root: Json"} {
		src := "fn f(" + hdr + ") {\n    Command::new(root).output();\n}\n"
		if fl := rustFlows(t, src); len(fl) != 0 {
			t.Errorf("%q seeded a source: %v", hdr, fl[0].Source.Kind)
		}
	}
	for _, hdr := range []string{"root: Path<u32>", "root: web::Path<String>", "Path(root): Path<String>"} {
		src := "fn f(" + hdr + ") {\n    Command::new(root).output();\n}\n"
		if fl := rustFlows(t, src); len(fl) == 0 {
			t.Errorf("%q no longer seeds a source", hdr)
		}
	}
}
