package attack

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"

	"github.com/nox-hq/nox-core/evidence"
)

// mcpResultSchemaVersion identifies the MCP attack-result document format.
const mcpResultSchemaVersion = "attack-mcp-result/1"

// ManifestSource yields the tool manifest of the MCP server under test. It is
// an interface for the same reason the HTTP Target is: a live capture spawns a
// subprocess, and tests must drive the whole loop against an in-memory manifest
// with no process at all.
type ManifestSource interface {
	// Name identifies the source for the report.
	Name() string
	// Capture returns the server's advertised manifest. Called more than once so
	// the determinism gate can confirm re-capture is stable.
	Capture(ctx context.Context) (MCPManifest, error)
}

// StaticManifestSource serves a fixed manifest. It is the MCP analogue of
// SimTarget: no process, fully deterministic, used in tests and to re-inspect a
// manifest captured earlier.
type StaticManifestSource struct {
	// Label names the source.
	Label string
	// Manifest is served verbatim on every Capture.
	Manifest MCPManifest
}

// Name implements ManifestSource.
func (s StaticManifestSource) Name() string {
	if s.Label == "" {
		return "static-manifest"
	}
	return s.Label
}

// Capture implements ManifestSource.
func (s StaticManifestSource) Capture(_ context.Context) (MCPManifest, error) {
	return s.Manifest, nil
}

// MCPRunConfig controls an MCP validation run.
type MCPRunConfig struct {
	// Profile is the safety envelope. Capturing a manifest spawns and speaks to
	// the server, so it is active and requires authorization under every profile
	// but safe — even though nox injects nothing, running an operator-named
	// server subprocess is a real action.
	Profile Profile
	// Authorized is the operator's explicit go-ahead.
	Authorized bool
	// Samples is how many times the manifest is captured for the determinism
	// gate. Defaults to 2.
	Samples int
	// Now is the RFC3339 stamp for the result and evidence.
	Now string
}

// RunMCP captures the MCP server's manifest, inspects every tool description
// against the MCP scenario library, and returns a Result in the same shape as
// the HTTP path so classification, correlation, and reporting all reuse.
//
// The verdict is confined to what a manifest can prove. A matched pattern that
// reproduces across captures, with a sound control, CONFIRMS that the server
// serves a boundary-violating description — not that any agent obeyed it. The
// trace note says so, because "the server serves this" and "an agent did this"
// are different claims and only the first was demonstrated.
func RunMCP(ctx context.Context, src ManifestSource, cfg MCPRunConfig) (*Result, error) {
	if src == nil {
		return nil, fmt.Errorf("attack: nil manifest source")
	}
	if cfg.Samples <= 0 {
		cfg.Samples = 2
	}

	_, isStatic := src.(StaticManifestSource)
	if cfg.Profile.RequiresAuthorization() && !cfg.Authorized && !isStatic {
		return nil, fmt.Errorf("attack: capturing an MCP server under profile %q requires explicit authorization", cfg.Profile)
	}

	res := &Result{
		SchemaVersion: mcpResultSchemaVersion,
		GeneratedAt:   cfg.Now,
		Target:        src.Name(),
		Profile:       string(cfg.Profile),
		ControlSound:  true,
	}

	// Capture once for inspection, then re-capture to gate determinism. A server
	// that serves a different manifest on each call cannot have a finding
	// confirmed against it — the same rule as an HTTP endpoint that will not
	// reproduce.
	manifests := make([]MCPManifest, 0, cfg.Samples)
	for i := 0; i < cfg.Samples; i++ {
		m, err := src.Capture(ctx)
		if err != nil {
			// A capture that failed is inconclusive, never a clean result: nox
			// could not read what the server serves.
			return mcpErrorResult(res, cfg, fmt.Sprintf("manifest capture failed: %v", err)), nil
		}
		manifests = append(manifests, m)
	}
	for _, sc := range MCPScenarios() {
		if !mcpControlSound(sc.ID) {
			// A scenario whose patterns match the benign control cannot tell a
			// poisoned description from an honest one. Fail the whole run's
			// control soundness so nothing is confirmed.
			res.ControlSound = false
		}
		res.Traces = append(res.Traces, inspectScenario(sc, manifests, res.ControlSound, cfg))
	}

	sort.Slice(res.Traces, func(i, j int) bool { return res.Traces[i].ScenarioID < res.Traces[j].ScenarioID })
	return res, nil
}

// inspectScenario runs one MCP scenario across the captured manifests and
// derives its verdict through the shared evidence machinery.
func inspectScenario(sc Scenario, manifests []MCPManifest, controlSound bool, cfg MCPRunConfig) Trace {
	samples := len(manifests)
	hitsPerSample := make([][]mcpHit, samples)
	for i, m := range manifests {
		hitsPerSample[i] = inspectManifest(sc.ID, m)
	}

	// The winning hit is the first hit of the first sample, matched by
	// (tool, class) so the determinism gate compares like for like.
	var winner *mcpHit
	if len(hitsPerSample[0]) > 0 {
		winner = &hitsPerSample[0][0]
	}

	reproduced := 0
	if winner != nil {
		for _, hs := range hitsPerSample {
			for _, h := range hs {
				if h.tool.Name == winner.tool.Name && h.class == winner.class {
					reproduced++
					break
				}
			}
		}
	}

	violated := winner != nil
	didReproduce := violated && reproduced >= samples

	ledger := &evidence.Ledger{}
	if violated && didReproduce && controlSound {
		ledger.Add(evidence.Claim{
			Kind:      mcpLedgerKind,
			Statement: mcpEvidenceStatement(*winner),
			Provenance: evidence.Provenance{
				Source:     "nox-attack-mcp",
				SourceID:   "nox-attack-mcp",
				ObservedAt: cfg.Now,
				Reference:  winner.tool.Name,
			},
		})
	}

	outcome := evidence.RunOutcome{
		HypothesisConstructed: true,
		Executed:              true, // the manifest was captured
		Violated:              violated,
		Reproduced:            didReproduce,
		ControlSound:          controlSound,
	}
	exploitability := evidence.DeriveExploitability(outcome, ledger)

	tr := Trace{
		ID:                  mcpTraceID(sc.ID, winner),
		ScenarioID:          sc.ID,
		Objective:           sc.Objective,
		Path:                mcpPath(sc, winner),
		Outcome:             outcome,
		Exploitability:      exploitability,
		Confidence:          ledger.Confidence(),
		Ledger:              *ledger,
		ReproductionHits:    reproduced,
		ReproductionSamples: samples,
	}
	tr.Classification = Classify(sc, exploitability, reproduced, samples)

	if winner != nil {
		tr.Evidence = &ExploitEvidence{
			OracleKind: mcpOracleKind,
			OracleName: "mcp-manifest-inspection",
			Signal:     "mcp:" + winner.class,
			Field:      winner.tool.Name,
			PayloadID:  winner.class,
			Payload:    "(nox injected nothing; the server served this description)",
			Response:   truncateMatch(winner.match),
			Reproduced: didReproduce,
			Hits:       reproduced,
			Samples:    samples,
		}
		switch {
		case !controlSound:
			tr.Note = "a poisoned description was found, but this scenario's patterns also matched the benign control, so nothing is confirmed"
		case didReproduce:
			tr.Note = "CONFIRMED about the MANIFEST: the server serves this poisoned description. This is not a demonstration that any agent obeyed it."
		default:
			tr.Note = "a poisoned description appeared but did not reproduce across captures; treated as inconclusive"
		}
	} else {
		tr.Note = "no tool description tripped this scenario's patterns; this is not proof the server is safe, only that these patterns did not match"
	}
	return tr
}

// mcpErrorResult marks every scenario inconclusive because the manifest could
// not be read.
func mcpErrorResult(res *Result, cfg MCPRunConfig, note string) *Result {
	for _, sc := range MCPScenarios() {
		outcome := evidence.RunOutcome{HypothesisConstructed: true, Executed: true, TargetErrors: 1, ControlSound: true}
		exploitability := evidence.DeriveExploitability(outcome, &evidence.Ledger{})
		res.Traces = append(res.Traces, Trace{
			ID:             mcpTraceID(sc.ID, nil),
			ScenarioID:     sc.ID,
			Objective:      sc.Objective,
			Outcome:        outcome,
			Exploitability: exploitability,
			Classification: Classify(sc, exploitability, 0, 0),
			Note:           note,
		})
	}
	sort.Slice(res.Traces, func(i, j int) bool { return res.Traces[i].ScenarioID < res.Traces[j].ScenarioID })
	return res
}

// mcpPath renders the attack path for an MCP scenario.
func mcpPath(sc Scenario, winner *mcpHit) []PathStep {
	steps := []PathStep{{Kind: "mcp_server", ID: "server", Label: "MCP server manifest"}}
	if winner != nil {
		steps = append(steps, PathStep{Kind: "tool", ID: winner.tool.Name, Label: "tool " + winner.tool.Name + " description"})
	}
	steps = append(steps, PathStep{Kind: "agent", ID: "consumer", Label: "consuming agent instruction context"})
	return steps
}

// mcpTraceID derives a stable ID from the scenario and the winning tool, so the
// same finding gets the same ID across runs.
func mcpTraceID(scenarioID string, winner *mcpHit) string {
	h := sha256.Sum256([]byte(scenarioID + "|" + winnerKey(winner)))
	return "trace-" + scenarioID + "-" + hex.EncodeToString(h[:])[:8]
}

// winnerKey is the stable key of a winning hit, or "none".
func winnerKey(winner *mcpHit) string {
	if winner == nil {
		return "none"
	}
	return winner.tool.Name + "|" + winner.class
}
