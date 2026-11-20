package core

import (
	"context"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
)

// What a scan contributed is recorded, so the CLI can say what left the
// machine. Every opted-in scan used to send its observations and its outcome
// report without a word, while the lookup line beside them said findings were
// not sent. The record must match what the service actually received.
func TestContributionRecordsWhatLeftTheMachine(t *testing.T) {
	d := newContractDouble(t)
	cfg := outcomeCfg(t, d)
	repo := gitRepo(t)
	opts := ScanOptions{ContributeObservations: true, ToolVersion: "1.70.0"}
	deg := &degrade.Degradations{}

	obs := contributeObservations(context.Background(), cfg, opts, outcomeFindings(), deg)
	sent, n := contributeOutcomes(context.Background(), cfg, opts, repo, outcomeFindings(), deg)
	if got := degradationText(deg); got != "" {
		t.Fatalf("degraded: %s", got)
	}

	var gotObs int
	for _, p := range d.paths {
		if p == "/v1/observations" {
			gotObs++
		}
	}
	if obs == 0 || obs != gotObs {
		t.Errorf("recorded %d observations, the service received %d", obs, gotObs)
	}
	bodies := d.outcomeBodies()
	if !sent || len(bodies) != 1 {
		t.Fatalf("outcome sent = %v, the service received %d reports", sent, len(bodies))
	}
	if want := len(bodies[0]["findings"].([]any)); n != want {
		t.Errorf("recorded %d outcome findings, the report carried %d", n, want)
	}
}

// Nothing sent, nothing recorded: a gate that stops the request must not leave
// a record that would make the CLI claim a send.
func TestContributionRecordsNothingWhenAGateStopsIt(t *testing.T) {
	d := newContractDouble(t)
	cfg := outcomeCfg(t, d)
	cfg.Scan.Intelligence.Contribute = false
	repo := gitRepo(t)
	opts := ScanOptions{ContributeObservations: true}
	deg := &degrade.Degradations{}
	if obs := contributeObservations(context.Background(), cfg, opts, outcomeFindings(), deg); obs != 0 {
		t.Errorf("recorded %d observations with contribution off", obs)
	}
	if sent, n := contributeOutcomes(context.Background(), cfg, opts, repo, outcomeFindings(), deg); sent || n != 0 {
		t.Errorf("recorded an outcome report (%v, %d) with contribution off", sent, n)
	}
	if len(d.paths) != 0 {
		t.Errorf("requests made: %v", d.paths)
	}
}
