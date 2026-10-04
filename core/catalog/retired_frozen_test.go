package catalog

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// A retired rule's pattern reproduces the fingerprints of the findings it
// used to report, so baselines, VEX statements and nox:ignore comments
// written against the old ID keep matching. rules.RetiredRule says the
// pattern is frozen; until this test nothing held it. A text replace while
// tightening the PEM header rules (#810) appended a key-body clause to two
// tombstones -- SEC-428 and SEC-429 -- and every test passed. Editing a
// tombstone un-waives findings in other people's repositories.
//
// testdata/retired_rules.json records every tombstone in the built
// catalogue. A recorded pattern may never change or disappear. A new
// retirement must be recorded: NOX_RECORD_RETIRED=1 appends the new ones and
// never rewrites an existing entry, so even regeneration cannot unfreeze one.

type tombstone struct {
	Owner   string `json:"owner"`
	Retired string `json:"retired"`
	Pattern string `json:"pattern"`
}

const frozenPath = "testdata/retired_rules.json"

func builtTombstones() map[string]tombstone {
	out := map[string]tombstone{}
	for _, r := range Rules() {
		for _, t := range r.Retires {
			out[t.ID] = tombstone{Owner: r.ID, Retired: t.ID, Pattern: t.Pattern}
		}
	}
	return out
}

func TestRetiredRulePatternsAreFrozen(t *testing.T) {
	built := builtTombstones()
	var recorded []tombstone
	if b, err := os.ReadFile(frozenPath); err == nil {
		if err := json.Unmarshal(b, &recorded); err != nil {
			t.Fatalf("%s: %v", frozenPath, err)
		}
	}
	seen := map[string]bool{}
	for _, r := range recorded {
		seen[r.Retired] = true
		got, ok := built[r.Retired]
		switch {
		case !ok:
			t.Errorf("%s's tombstone is gone; its fingerprints can no longer be reproduced", r.Retired)
		case got.Pattern != r.Pattern:
			t.Errorf("%s's tombstone pattern changed -- it is frozen at retirement.\nrecorded: %s\nbuilt:    %s",
				r.Retired, r.Pattern, got.Pattern)
		}
	}
	var fresh []tombstone
	for id, tb := range built {
		if !seen[id] {
			fresh = append(fresh, tb)
		}
	}
	if len(fresh) == 0 {
		if len(recorded) == 0 {
			t.Fatal("no tombstones in the built catalogue; this test would check nothing")
		}
		return
	}
	sort.Slice(fresh, func(i, j int) bool { return fresh[i].Retired < fresh[j].Retired })
	if os.Getenv("NOX_RECORD_RETIRED") == "" {
		for _, f := range fresh {
			t.Errorf("%s (retired into %s) is not recorded in %s; run with NOX_RECORD_RETIRED=1 to append it",
				f.Retired, f.Owner, frozenPath)
		}
		return
	}
	recorded = append(recorded, fresh...)
	sort.Slice(recorded, func(i, j int) bool { return recorded[i].Retired < recorded[j].Retired })
	b, err := json.MarshalIndent(recorded, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Dir(frozenPath), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(frozenPath, append(b, '\n'), 0o644); err != nil {
		t.Fatal(err)
	}
	t.Logf("recorded %d new tombstone(s)", len(fresh))
}
