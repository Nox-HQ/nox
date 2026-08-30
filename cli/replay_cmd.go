package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"

	"github.com/nox-hq/nox/core/replay"
)

// runReplay re-derives a scan's verdicts from its evidence artifact.
//
// It reads nothing but the artifact — not the repository, not the rules, not
// the network. That is what makes the question answerable later, when all three
// have moved on: "does this evidence still support this verdict?" never
// depended on any of them.
func runReplay(args []string) int {
	fs := flag.NewFlagSet("replay", flag.ContinueOnError)
	var jsonOut bool
	fs.BoolVar(&jsonOut, "json", false, "emit the replay result as JSON")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, `Usage: nox replay <evidence.json> [flags]

Re-derives the verdicts in an evidence artifact from the evidence it contains,
and reports any that come out differently.

Produce an artifact with:
  nox scan . --evidence-out evidence.json

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}

	art, err := replay.Load(fs.Arg(0))
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	res := replay.Replay(art)

	if jsonOut {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(res); err != nil {
			fmt.Fprintf(os.Stderr, "error: %v\n", err)
			return 2
		}
	} else {
		fmt.Println(res.Summary())
		for _, m := range res.Missing {
			fmt.Printf("  no evidence  %s\n", m)
		}
		for _, d := range res.Divergences {
			fmt.Printf("  %-20s %s %s\n", d.Field, d.RuleID, d.Fingerprint[:min(12, len(d.Fingerprint))])
			fmt.Printf("      stored:   %s\n", d.Stored)
			fmt.Printf("      replayed: %s\n", d.Replayed)
		}
	}

	switch {
	case res.VersionChanged:
		// Not a failure. The adjudicator moved, so a difference is a change and
		// the operator asked to see it. Exiting non-zero here would make every
		// nox upgrade look like a regression in whatever produced the artifact.
		return 0
	case res.Reproduced():
		return 0
	default:
		return 1
	}
}
