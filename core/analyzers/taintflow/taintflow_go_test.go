package taintflow

import "testing"

// TestAnalyzerGoTruePositive proves the analyzer runs the taint engine on a .go
// artifact end-to-end (discovery → lexctx LangGo → extractGo → engine → finding),
// with no code path change beyond the catalog + extractor: a request query
// parameter concatenated into db.Query fires TAINT-001.
func TestAnalyzerGoTruePositive(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "store.go", `package store

func lookup(db *DB, r *Req) {
	id := r.URL.Query().Get("id")
	_ = db.Query("SELECT * FROM t WHERE id = '" + id + "'")
}
`)
	ids := scan(t, art)
	if len(ids) != 1 || ids[0] != "TAINT-001" {
		t.Fatalf("want [TAINT-001], got %v", ids)
	}
}

// TestAnalyzerGoCleanNoFinding proves the parameterized-query guardrail: a
// placeholder ($1) query with the value passed as a distinct argument fires
// nothing.
func TestAnalyzerGoCleanNoFinding(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "safe.go", `package store

func lookup(db *DB, id string) {
	_ = db.Query("SELECT name FROM users WHERE id = $1", id)
}
`)
	ids := scan(t, art)
	if len(ids) != 0 {
		t.Fatalf("want no findings, got %v", ids)
	}
}

// TestAnalyzerGoDeserialization proves the inline-source hoist wiring: r.Body used
// directly as a sink argument fires TAINT-005.
func TestAnalyzerGoDeserialization(t *testing.T) {
	dir := t.TempDir()
	art := writeArtifact(t, dir, "session.go", `package session

func restore(r *Req) {
	var env E
	if err := gob.NewDecoder(r.Body).Decode(&env); err != nil {
		_ = err
	}
}
`)
	ids := scan(t, art)
	found := false
	for _, id := range ids {
		if id == "TAINT-005" {
			found = true
		}
	}
	if !found {
		t.Fatalf("want TAINT-005, got %v", ids)
	}
}
