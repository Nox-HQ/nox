package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/nox-hq/nox/core/confirm"
	"github.com/nox-hq/nox/core/confirm/harnessmock"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

func writeFindings(t *testing.T, dir string) string {
	t.Helper()
	loc := findings.Location{FilePath: "app.py", StartLine: 50, EndLine: 50}
	md := map[string]string{"function": "chat", "source_kind": "http_body"}
	rep := report.JSONReport{Findings: []findings.Finding{
		{RuleID: "AGENTFLOW-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
			Location: loc, Message: "untrusted input reaches LLM prompt call", Fingerprint: "aaa", Metadata: md},
		{RuleID: "TAINT-AI-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceMedium,
			Location: loc, Message: "untrusted input reaches sink", Fingerprint: "bbb", Metadata: md},
	}}
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(path, data, 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func startTarget(t *testing.T, makeApp func(string) http.Handler) string {
	t.Helper()
	model := httptest.NewServer(harnessmock.NewMockModel())
	t.Cleanup(model.Close)
	app := httptest.NewServer(makeApp(model.URL + "/v1/chat/completions"))
	t.Cleanup(app.Close)
	return app.URL
}

// TestRunConfirm_Vulnerable: end-to-end through the CLI entry point. Vulnerable
// target → exit code 1 (CONFIRMED) and a confirmations.json with evidence.
func TestRunConfirm_Vulnerable(t *testing.T) {
	dir := t.TempDir()
	findingsPath := writeFindings(t, dir)
	out := filepath.Join(dir, "confirmations.json")
	target := startTarget(t, harnessmock.NewVulnerableApp)

	code := runConfirm([]string{
		"--target", target, "--findings", findingsPath, "--output", out,
		"--route", "/chat", "--fields", "persona,message", "--authorize",
	})
	if code != 1 {
		t.Fatalf("expected exit 1 (CONFIRMED), got %d", code)
	}
	var rep confirm.Report
	readJSON(t, out, &rep)
	if !rep.AnyConfirmed() {
		t.Fatal("expected a CONFIRMED verdict in the report")
	}
	if rep.Results[0].Evidence == nil || rep.Results[0].Evidence.Field != "persona" {
		t.Fatal("expected evidence localized to the persona field")
	}
}

// TestRunConfirm_Fixed: fixed target → exit code 0 (UNCONFIRMED), no evidence.
func TestRunConfirm_Fixed(t *testing.T) {
	dir := t.TempDir()
	findingsPath := writeFindings(t, dir)
	out := filepath.Join(dir, "confirmations.json")
	target := startTarget(t, harnessmock.NewFixedApp)

	code := runConfirm([]string{
		"--target", target, "--findings", findingsPath, "--output", out,
		"--route", "/chat", "--fields", "persona,message", "--authorize",
	})
	if code != 0 {
		t.Fatalf("expected exit 0 (UNCONFIRMED), got %d", code)
	}
	var rep confirm.Report
	readJSON(t, out, &rep)
	if rep.AnyConfirmed() {
		t.Fatal("fixed app must not be confirmed")
	}
	if rep.Results[0].Evidence != nil {
		t.Fatal("UNCONFIRMED must carry no evidence")
	}
}

// TestRunConfirm_RefusesWithoutAuthorize: the active-intent gate.
func TestRunConfirm_RefusesWithoutAuthorize(t *testing.T) {
	dir := t.TempDir()
	findingsPath := writeFindings(t, dir)
	code := runConfirm([]string{
		"--target", "http://127.0.0.1:0", "--findings", findingsPath,
		"--route", "/chat", "--fields", "persona",
	})
	if code != 2 {
		t.Fatalf("expected exit 2 (refused without --authorize), got %d", code)
	}
}

// TestRunConfirm_RequiresTarget: --target is mandatory.
func TestRunConfirm_RequiresTarget(t *testing.T) {
	if code := runConfirm([]string{"--authorize"}); code != 2 {
		t.Fatalf("expected exit 2 without --target, got %d", code)
	}
}

// TestRunConfirm_AppSrcRecovery: route/fields recovered from Flask source.
func TestRunConfirm_AppSrcRecovery(t *testing.T) {
	dir := t.TempDir()
	findingsPath := writeFindings(t, dir)
	out := filepath.Join(dir, "confirmations.json")
	target := startTarget(t, harnessmock.NewVulnerableApp)

	code := runConfirm([]string{
		"--target", target, "--findings", findingsPath, "--output", out,
		"--app-src", filepath.Join("..", "core", "confirm", "testdata", "vulnerable_app.py"),
		"--authorize",
	})
	if code != 1 {
		t.Fatalf("expected exit 1 with app-src recovery, got %d", code)
	}
	var rep confirm.Report
	readJSON(t, out, &rep)
	if rep.Results[0].Route != "/chat" {
		t.Fatalf("expected recovered route /chat, got %q", rep.Results[0].Route)
	}
}

func readJSON(t *testing.T, path string, v any) {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, v); err != nil {
		t.Fatal(err)
	}
}
