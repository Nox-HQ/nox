package server

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/threatmodel"
)

// writePreviousModel writes the model of the server's cached scan to dir and
// returns its path: the model.json `nox model` leaves behind.
func writePreviousModel(t *testing.T, s *Server, dir string) string {
	t.Helper()
	in, err := s.getCache("").result.ThreatModelInput(s.version)
	if err != nil {
		t.Fatal(err)
	}
	data, err := threatmodel.Build(in).JSON()
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(dir, "model.json")
	if err := os.WriteFile(p, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func scannedAt(t *testing.T, allowed []string) *Server {
	t.Helper()
	if testing.Short() {
		t.Skip("end-to-end scan; skipped in -short")
	}
	res, err := nox.RunScanWithOptions("../testdata/precision-suite", nox.ScanOptions{Offline: true, RecordReasoning: true})
	if err != nil {
		t.Fatalf("scan: %v", err)
	}
	s := New("test", allowed)
	s.setCache("", res)
	return s
}

// The tool says what changed since an earlier model, from the same core
// comparison as `nox model --previous`.
func TestThreatModelToolComparesWithAPreviousModel(t *testing.T) {
	dir := t.TempDir()
	s := scannedAt(t, []string{dir})
	prev := writePreviousModel(t, s, dir)

	res, err := s.handleThreatModel(context.Background(), threatModelInput{Previous: prev})
	if err != nil {
		t.Fatal(err)
	}
	var out threatModelOutput
	decode(t, res, &out)
	if out.Model.Changes == nil {
		t.Fatalf("no changes block: %s", payload(t, res))
	}
	if !strings.Contains(out.Summary, "Changes since the previous model") {
		t.Errorf("summary omits the comparison:\n%s", out.Summary)
	}
	in, _ := s.getCache("").result.ThreatModelInput(s.version)
	want, err := threatmodel.BuildAgainst(in, prev)
	if err != nil {
		t.Fatal(err)
	}
	wantChanges, _ := json.Marshal(want.Changes)
	gotChanges, _ := json.Marshal(out.Model.Changes)
	if !bytes.Equal(wantChanges, gotChanges) {
		t.Errorf("the MCP comparison differs from the one the CLI makes:\n%s\nvs\n%s", gotChanges, wantChanges)
	}

	// Without a previous, nothing is compared.
	res, _ = s.handleThreatModel(context.Background(), threatModelInput{})
	var plain threatModelOutput
	decode(t, res, &plain)
	if plain.Model.Changes != nil {
		t.Error("a model with no previous carries a changes block")
	}
}

// previous is a path the tool reads, so it is confined exactly as the scan
// tool's previous is, and a file that is not a model is an error, not an empty
// comparison.
func TestThreatModelToolConfinesAndValidatesPrevious(t *testing.T) {
	dir := t.TempDir()
	s := scannedAt(t, []string{dir})
	outside := filepath.Join(t.TempDir(), "model.json")
	if err := os.WriteFile(outside, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ := s.handleThreatModel(context.Background(), threatModelInput{Previous: outside})
	if !res.IsError || !strings.Contains(payload(t, res), "outside allowed workspaces") {
		t.Errorf("a previous model outside the allowed paths was read: %s", payload(t, res))
	}

	notModel := filepath.Join(dir, "findings.json")
	if err := os.WriteFile(notModel, []byte(`{"meta":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	res, _ = s.handleThreatModel(context.Background(), threatModelInput{Previous: notModel})
	if !res.IsError || !strings.Contains(payload(t, res), "not a nox threat model") {
		t.Errorf("something that is not a model was accepted: %s", payload(t, res))
	}

	res, _ = s.handleThreatModel(context.Background(), threatModelInput{Previous: filepath.Join(dir, "missing.json")})
	if !res.IsError {
		t.Errorf("a missing previous model was ignored: %s", payload(t, res))
	}
}
