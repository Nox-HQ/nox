package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeRust is the end-to-end helper for Rust: source bytes → units → flows,
// using the default embedded catalog. It mirrors analyze() (which defaults to
// Python/JS extensions) but attaches a .rs path.
func analyzeRust(t *testing.T, src string) []flowResult {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.rs", lexctx.LangRust, []byte(src))
	var out []flowResult
	for i := range units {
		flows := eng.Analyze(units[i])
		for j := range flows {
			out = append(out, flowResult{ruleID: flows[j].Sink.RuleID, sinkCall: flows[j].SinkCall})
		}
	}
	return out
}

type flowResult struct {
	ruleID   string
	sinkCall string
}

func hasRuleID(flows []flowResult, id string) bool {
	for _, f := range flows {
		if f.ruleID == id {
			return true
		}
	}
	return false
}

// TestStructuralRustExtractorParamActixCmdInjection is the closed-FN case: an
// actix handler where the untrusted value arrives as a `web::Query<_>` extractor
// parameter and flows into a Command::new("sh").arg(...) sink. Modeling the
// extractor-typed parameter as a taint source lets TAINT-002 fire.
func TestStructuralRustExtractorParamActixCmdInjection(t *testing.T) {
	src := `use actix_web::web;
use std::process::Command;
async fn run(query: web::Query<Params>) {
    let out = Command::new("sh").arg("-c").arg(&query.cmd).output();
    let _ = out;
}
`
	flows := analyzeRust(t, src)
	if !hasRuleID(flows, "TAINT-002") {
		t.Fatalf("expected TAINT-002 (command injection) from extractor param, got %+v", flows)
	}
}

// TestStructuralRustExtractorParamAxumDestructured: the axum destructured form
// `Query(params): Query<Params>` seeds `params`, and `params.cmd` reaching a
// Command sink fires TAINT-002.
func TestStructuralRustExtractorParamAxumDestructured(t *testing.T) {
	src := `async fn run(Query(params): Query<Params>) {
    let out = Command::new("sh").arg("-c").arg(&params.cmd).output();
    let _ = out;
}
`
	flows := analyzeRust(t, src)
	if !hasRuleID(flows, "TAINT-002") {
		t.Fatalf("expected TAINT-002 from axum destructured extractor param, got %+v", flows)
	}
}

// TestStructuralRustExtractorParamPathTraversal: a `web::Path<String>` extractor
// param reaching a std::fs::read sink fires TAINT-004.
func TestStructuralRustExtractorParamPathTraversal(t *testing.T) {
	src := `async fn h(p: web::Path<String>) {
    let data = std::fs::read(&p);
    let _ = data;
}
`
	flows := analyzeRust(t, src)
	if !hasRuleID(flows, "TAINT-004") {
		t.Fatalf("expected TAINT-004 from web::Path extractor param, got %+v", flows)
	}
}

// TestStructuralRustNonExtractorParamNoFlow is the precision guardrail at the
// engine level: a normal typed parameter reaching a sink-shaped call must NOT
// fire — it is not untrusted input.
func TestStructuralRustNonExtractorParamNoFlow(t *testing.T) {
	src := `fn h(user_id: i64, cfg: &Config) {
    let data = std::fs::read(cfg.path());
    let out = Command::new(cfg.shell()).arg(user_id).output();
    let _ = (data, out);
}
`
	flows := analyzeRust(t, src)
	if len(flows) != 0 {
		t.Fatalf("non-extractor params must not taint; got flows %+v", flows)
	}
}
