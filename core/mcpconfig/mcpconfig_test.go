package mcpconfig

import (
	"encoding/json"
	"testing"
)

// Key order must not change the hash — that is the whole point of a canonical
// identity, and the property rug-pull detection depends on.
func TestCanonicalHashKeyOrderIndependent(t *testing.T) {
	a := json.RawMessage(`{"command":"node","args":["s.js"],"env":{"A":"1","B":"2"}}`)
	b := json.RawMessage(`{"env":{"B":"2","A":"1"},"args":["s.js"],"command":"node"}`)
	if CanonicalHash(a) != CanonicalHash(b) {
		t.Fatal("reordered-but-equal server defs must hash the same")
	}
	// A genuine change must change the hash.
	c := json.RawMessage(`{"command":"node","args":["evil.js"]}`)
	if CanonicalHash(a) == CanonicalHash(c) {
		t.Fatal("a changed command must change the hash — this is the rug-pull signal")
	}
}

// An unparseable fragment must still hash to something stable and non-empty, so
// an attacker cannot dodge detection by serving malformed JSON.
func TestCanonicalHashFailsToRawBytesNotEmpty(t *testing.T) {
	bad := json.RawMessage(`{not valid json`)
	h := CanonicalHash(bad)
	if h == "" {
		t.Fatal("unparseable fragment must still produce a hash")
	}
	if CanonicalHash(bad) != CanonicalHash(json.RawMessage(`{not valid json`)) {
		t.Fatal("the raw-byte fallback must be stable")
	}
}

func TestParseServersThreeCases(t *testing.T) {
	// Valid config with servers.
	got, err := ParseServers([]byte(`{"mcpServers":{"a":{"command":"x"}}}`))
	if err != nil || len(got) != 1 {
		t.Fatalf("valid config: got %d servers, err %v", len(got), err)
	}
	// Valid JSON without an mcpServers object -> empty, no error.
	got, err = ParseServers([]byte(`{"something":"else"}`))
	if err != nil || len(got) != 0 {
		t.Fatalf("non-MCP config should be empty, no error: got %d, %v", len(got), err)
	}
	// Malformed JSON -> error (never silently empty).
	if _, err := ParseServers([]byte(`{"mcpServers": {`)); err == nil {
		t.Fatal("malformed config must return an error, not empty")
	}
}

func TestCanonicalizeEmptyAndInvalid(t *testing.T) {
	if Canonicalize(nil) != nil || Canonicalize(json.RawMessage(`{bad`)) != nil {
		t.Fatal("empty/invalid input must canonicalize to nil")
	}
}
