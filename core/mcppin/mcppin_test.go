package mcppin

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const cfgV1 = `{"mcpServers":{"fs":{"command":"mcp-fs","args":["./project"]}}}`
const cfgV2 = `{"mcpServers":{"fs":{"command":"mcp-fs","args":["/"]}}}`

func pinned(t *testing.T, path, content string) *Lock {
	t.Helper()
	defs, err := Definitions(path, []byte(content))
	if err != nil {
		t.Fatal(err)
	}
	l := NewLock()
	for k, h := range defs {
		l.Pins[k] = h
	}
	return l
}

func TestCheck_UnchangedIsSilent(t *testing.T) {
	l := pinned(t, "mcp.json", cfgV1)
	ff, err := l.Check("mcp.json", []byte(cfgV1))
	if err != nil || len(ff) != 0 {
		t.Fatalf("want no findings, got %v err=%v", ff, err)
	}
}

func TestCheck_KeyOrderDoesNotDrift(t *testing.T) {
	l := pinned(t, "mcp.json", `{"mcpServers":{"fs":{"command":"a","args":["x"]}}}`)
	ff, _ := l.Check("mcp.json", []byte(`{"mcpServers":{"fs":{"args":["x"],"command":"a"}}}`))
	if len(ff) != 0 {
		t.Fatalf("key order must not be drift: %v", ff)
	}
}

// The property the hidden-state design lacked: checking never changes the lock,
// so a change is reported again on every call until a person re-pins.
func TestCheck_DriftPersistsAcrossRepeatedChecks(t *testing.T) {
	l := pinned(t, "mcp.json", cfgV1)
	for i := 0; i < 3; i++ {
		ff, err := l.Check("mcp.json", []byte(cfgV2))
		if err != nil {
			t.Fatal(err)
		}
		if len(ff) != 1 || ff[0].RuleID != RuleID || ff[0].Metadata["change"] != "modified" {
			t.Fatalf("check %d: want one modified MCP-015, got %v", i, ff)
		}
	}
}

func TestCheck_RepinAcknowledges(t *testing.T) {
	l := pinned(t, "mcp.json", cfgV2)
	if ff, _ := l.Check("mcp.json", []byte(cfgV2)); len(ff) != 0 {
		t.Fatalf("re-pinned definition must be silent: %v", ff)
	}
}

func TestCheck_UnpinnedServerIsReported(t *testing.T) {
	l := pinned(t, "mcp.json", cfgV1)
	both := `{"mcpServers":{"fs":{"command":"mcp-fs","args":["./project"]},"new":{"command":"x"}}}`
	ff, _ := l.Check("mcp.json", []byte(both))
	if len(ff) != 1 || ff[0].Metadata["change"] != "unpinned" || ff[0].Metadata["server"] != "new" {
		t.Fatalf("want one unpinned finding for \"new\": %v", ff)
	}
}

func TestCheck_RemovedServerIsNotAFinding(t *testing.T) {
	l := pinned(t, "mcp.json", cfgV1)
	if ff, _ := l.Check("mcp.json", []byte(`{"mcpServers":{}}`)); len(ff) != 0 {
		t.Fatalf("removing a server must not alert: %v", ff)
	}
}

func TestCheck_MalformedConfigIsError(t *testing.T) {
	l := pinned(t, "mcp.json", cfgV1)
	if _, err := l.Check("mcp.json", []byte(`{"mcpServers":{"fs":{},}}`)); err == nil {
		t.Fatal("malformed config must be an error, not an empty result")
	}
}

func TestLoad_AbsentIsNotApproval(t *testing.T) {
	l, exists, err := Load(filepath.Join(t.TempDir(), "mcp-pins.json"))
	if err != nil || exists || l != nil {
		t.Fatalf("absent file: lock=%v exists=%v err=%v", l, exists, err)
	}
}

func TestLoad_CorruptAndWrongVersionAreErrors(t *testing.T) {
	dir := t.TempDir()
	for name, body := range map[string]string{
		"corrupt": `{"pins": not-json`,
		"v1":      `{"version":"1","pins":{}}`,
	} {
		p := filepath.Join(dir, name+".json")
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		if _, exists, err := Load(p); err == nil || !exists {
			t.Fatalf("%s: want error with exists=true, got exists=%v err=%v", name, exists, err)
		}
	}
}

func TestSave_DeterministicAndRoundTrips(t *testing.T) {
	p := filepath.Join(t.TempDir(), ".nox", "mcp-pins.json")
	l := pinned(t, "a.json", `{"mcpServers":{"z":{"command":"1"},"a":{"command":"2"}}}`)
	if err := l.Save(p); err != nil {
		t.Fatal(err)
	}
	first, _ := os.ReadFile(p)
	if err := l.Save(p); err != nil {
		t.Fatal(err)
	}
	second, _ := os.ReadFile(p)
	if !bytes.Equal(first, second) || !bytes.HasSuffix(first, []byte("\n")) {
		t.Fatal("pin file must be byte-stable with a trailing newline")
	}
	if bytes.Index(first, []byte("a.json::a")) > bytes.Index(first, []byte("a.json::z")) {
		t.Fatal("keys must be sorted")
	}
	got, exists, err := Load(p)
	if err != nil || !exists || len(got.Pins) != 2 {
		t.Fatalf("round trip: %v %v %v", got, exists, err)
	}
}
