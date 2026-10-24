package main

import (
	"fmt"
	"os"

	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/change"
)

// previousLabel names the earlier state in the "Since ..." heading.
const previousLabel = "the previous run"

// loadPreviousState reads the run --previous points at. It returns havePrev
// false, and no error, when the flag is unset or the file does not exist yet:
// the first run of a scheduled scan has nothing to compare against, and that
// is said on stderr rather than failing the build. A file that exists and
// cannot be read is an error, never an empty state: "no earlier run" and "an
// earlier run that found nothing" must not be confusable.
func loadPreviousState(path string, scopedMode bool) (change.State, bool, error) {
	if path == "" {
		return change.State{}, false, nil
	}
	if scopedMode {
		fmt.Fprintln(os.Stderr, "note: --previous is ignored with --staged and --history, which do not produce an assessment")
		return change.State{}, false, nil
	}
	st, err := change.LoadPrevious(path, previousLabel)
	if err != nil {
		if os.IsNotExist(err) {
			fmt.Fprintf(os.Stderr, "note: no previous run at %s; nothing to compare against, so nothing is called new\n", path)
			return change.State{}, false, nil
		}
		return change.State{}, false, fmt.Errorf("--previous %s: %w", path, err)
	}
	return st, true, nil
}

// sinceDelta compares this run with the earlier one, or returns nil when there
// was no earlier run, which leaves the output exactly as it was.
func sinceDelta(prev change.State, havePrev bool, result *nox.ScanResult) *change.Delta {
	if !havePrev || result == nil {
		return nil
	}
	d := change.Compare(prev, change.FromScan(result, "this run"))
	return &d
}
