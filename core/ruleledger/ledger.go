// Package ruleledger reads and checks scripts/rule-deltas.json, the record of
// why each rule reports less than it did in the last release.
//
// The ledger is only meaningful against the release it was written for.
// Entries accumulate during development against the last released nox, and are
// cleared when a release is cut — at which point the drops they explain are
// inside the new baseline and no longer drops at all.
//
// Nothing used to own that transition. scripts/rule-diff.sh notices a stale
// ledger, but it only runs when a pull request touches rule definitions, so the
// failure lands on whichever unrelated change happens to be next: v1.35.0
// shipped on 2026-09-10 with sixteen entries left in place, and the first PR to
// trip over it was a secrets-precision fix two days later that had nothing to
// do with any of them.
//
// The lifecycle belongs to the release. CheckForRelease is the invariant a
// release runs against the tag it is cutting.
package ruleledger

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
	"strings"
)

// Entry explains why one rule reports less than it did in the baseline.
type Entry struct {
	Rule           string `json:"rule"`
	Classification string `json:"classification"`
	PR             int    `json:"pr,omitempty"`
	Reason         string `json:"reason"`
}

// Ledger is the parsed rule-deltas.json document.
type Ledger struct {
	// NoxRelease is the release the entries are written against.
	NoxRelease string `json:"nox_release"`
	// Classifications is the closed set of reasons an entry may give.
	Classifications map[string]string `json:"classifications"`
	// Entries is one record per rule whose count dropped.
	Entries []Entry `json:"entries"`
}

// Load reads a ledger from disk.
func Load(path string) (*Ledger, error) {
	raw, err := os.ReadFile(path) // #nosec G304 -- caller-supplied repository path
	if err != nil {
		return nil, fmt.Errorf("ruleledger: reading %s: %w", path, err)
	}
	var l Ledger
	if err := json.Unmarshal(raw, &l); err != nil {
		return nil, fmt.Errorf("ruleledger: parsing %s: %w", path, err)
	}
	return &l, nil
}

// CheckWellFormed reports every entry that explains nothing.
//
// An entry with no rule, no reason, or a classification nobody defined cannot
// be reviewed: the failure it produces would name an ID and contribute an empty
// sentence. This holds at all times, not only at a release.
func (l *Ledger) CheckWellFormed() []error {
	var errs []error
	if l.NoxRelease == "" {
		errs = append(errs, fmt.Errorf("the ledger declares no nox_release, so nothing "+
			"can tell whether its entries describe a comparison anyone is making"))
	}
	seen := map[string]bool{}
	for _, e := range l.Entries {
		switch {
		case e.Rule == "":
			errs = append(errs, fmt.Errorf("an entry has no rule: %+v", e))
		case e.Reason == "":
			errs = append(errs, fmt.Errorf("%s has an empty reason; a drop explained by "+
				"nothing is an unexplained drop with a row in a table", e.Rule))
		case l.Classifications[e.Classification] == "":
			errs = append(errs, fmt.Errorf("%s claims classification %q, which is not "+
				"listed under .classifications", e.Rule, e.Classification))
		}
		if e.Rule != "" && seen[e.Rule] {
			errs = append(errs, fmt.Errorf("%s appears twice; one of the two reasons is "+
				"the one nobody reads", e.Rule))
		}
		seen[e.Rule] = true
	}
	return errs
}

// CheckForRelease is the invariant a release runs against the tag it is cutting.
//
// Cutting a release moves the baseline. Every entry then describes a drop that
// is INSIDE the new baseline — it no longer drops, so the entry no longer
// describes anything, and a ledger nothing validates rots into decoration. So a
// release requires both halves of the roll: the entries cleared, and
// nox_release advanced to the tag being cut.
//
// It deliberately does not clear the ledger itself. Clearing is mechanical, but
// doing it silently would mean a release could discard sixteen explanations
// nobody had read, and the point of the file is that a human accounts for each
// drop. The release fails and says exactly what to do instead.
func (l *Ledger) CheckForRelease(tag string) error {
	if tag == "" {
		return fmt.Errorf("ruleledger: no release tag given; the invariant has nothing to check against")
	}
	var problems []string
	if l.NoxRelease != tag {
		problems = append(problems, fmt.Sprintf(
			"nox_release is %q and the release being cut is %q", l.NoxRelease, tag))
	}
	if n := len(l.Entries); n > 0 {
		problems = append(problems, fmt.Sprintf(
			"%d entr%s still present, explaining drops that this release makes part of the baseline: %s",
			n, plural(n), strings.Join(l.ruleNames(), ", ")))
	}
	if len(problems) == 0 {
		return nil
	}
	// The message is multi-line on purpose: it is read by whoever is cutting a
	// release, at the moment it blocks them, and it has to say what to do.
	return fmt.Errorf("ruleledger: the delta ledger was not rolled for %s:\n  - %s\n\n"+
		"Cutting a release moves the baseline, so every entry now describes a drop that no\n"+
		"longer drops. Read them, then clear .entries and set nox_release to %s in the\n"+
		"release commit. Leaving them costs the next unrelated pull request that happens to\n"+
		"touch a rule definition, which is how v1.35.0's sixteen entries were found", //nolint:staticcheck // ST1005: multi-line operator guidance, not a wrapped error
		tag, strings.Join(problems, "\n  - "), tag)
}

// ruleNames returns the entries' rule IDs, sorted, for a stable message.
func (l *Ledger) ruleNames() []string {
	out := make([]string, 0, len(l.Entries))
	for _, e := range l.Entries {
		out = append(out, e.Rule)
	}
	sort.Strings(out)
	return out
}

func plural(n int) string {
	if n == 1 {
		return "y is"
	}
	return "ies are"
}
