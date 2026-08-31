package attack

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
)

// planSchemaVersion identifies the attack-plan document format.
const planSchemaVersion = "attack-plan/1"

// injectionRuleSet is the set of static rule IDs that assert "untrusted input
// reaches an LLM prompt call". These are the statically-flagged candidates a
// prompt-injection hypothesis is grounded in — the same set core/confirm uses,
// kept in sync deliberately.
var injectionRuleSet = map[string]bool{
	"AGENTFLOW-001": true,
	"TAINT-AI-001":  true,
	"AI-PI-001":     true,
	"AI-PI-002":     true,
	"AI-PI-003":     true,
	"AI-PI-004":     true,
}

// isInjectionRule reports whether ruleID is a prompt-injection candidate.
func isInjectionRule(ruleID string) bool { return injectionRuleSet[ruleID] }

// SkipNote records a finding that mapped to no attack scenario, and why. Nothing
// is ever silently dropped: a finding either grounds a hypothesis or appears
// here.
type SkipNote struct {
	// Fingerprint identifies the skipped finding.
	Fingerprint string `json:"fingerprint"`
	// RuleID is the finding's rule.
	RuleID string `json:"rule_id"`
	// Reason explains why no scenario applied.
	Reason string `json:"reason"`
}

// PlanInput is everything BuildPlan needs. Now is an RFC3339 timestamp supplied
// by the caller, so a plan is reproducible without the package reading a clock.
type PlanInput struct {
	// Root is the scanned workspace root.
	Root string
	// Findings are the static findings to ground hypotheses in.
	Findings []findings.Finding
	// Inventory is the AI component inventory (may be nil).
	Inventory *ai.Inventory
	// Now is an RFC3339 timestamp stamped onto the plan.
	Now string

	// Evidence returns what the scan established about a finding, and the
	// subject its claims were filed against. Optional: a caller that has no
	// reasoning store passes nil and every hypothesis carries an empty ledger,
	// which is the old behaviour.
	//
	// It is a function rather than a map because the caller owns the subject
	// derivation. Duplicating that here would put two implementations of
	// "which subject is this finding about" in the tree, and they would
	// disagree the first time one changed.
	Evidence func(findings.Finding) (evidence.Subject, evidence.Ledger)

	// Unknowns returns the open questions about a subject, cheapest first —
	// adjudicate.MissingEvidence, supplied by the caller so this package does
	// not depend on the capability registry. Optional.
	Unknowns func(evidence.Subject) []string
}

// Plan is the attack blueprint: the assets and boundaries derived from the scan,
// the scenarios in play, the grounded hypotheses, and the findings that were
// skipped. It is emitted as JSON and consumed by Run.
type Plan struct {
	// SchemaVersion identifies the document format.
	SchemaVersion string `json:"schema_version"`
	// GeneratedAt is the caller-supplied timestamp.
	GeneratedAt string `json:"generated_at"`
	// Root is the scanned workspace root.
	Root string `json:"root"`
	// Assets are the things of value the plan targets.
	Assets []Asset `json:"assets"`
	// Boundaries are the trust boundaries the plan would cross.
	Boundaries []TrustBoundary `json:"boundaries"`
	// Scenarios are the library scenarios in play, sorted by ID.
	Scenarios []Scenario `json:"scenarios"`
	// Hypotheses are the grounded conjectures to attempt, sorted by ID.
	Hypotheses []Hypothesis `json:"hypotheses"`
	// Skipped lists findings that mapped to no scenario.
	Skipped []SkipNote `json:"skipped"`
	// Graph is the attack-oriented model of the target derived from the same
	// findings and inventory (PRD §12). Hypothesis paths are walks over it.
	Graph *AttackGraph `json:"graph,omitempty"`
}

// shortID returns a stable 8-char hash fragment for constructing deterministic
// identifiers from arbitrary strings.
func shortID(parts ...string) string {
	sum := sha256.Sum256([]byte(strings.Join(parts, "|")))
	return hex.EncodeToString(sum[:])[:8]
}

// BuildPlan turns static findings and an AI inventory into an attack plan. Every
// hypothesis is grounded — an injection hypothesis in an injection finding, a
// tool or exfiltration hypothesis in the inventory's tool matrix — and every
// finding that grounds nothing is recorded in Skipped. Output is deterministic:
// all collections are sorted before emission.
func BuildPlan(in PlanInput) (*Plan, error) {
	plan := &Plan{
		SchemaVersion: planSchemaVersion,
		GeneratedAt:   in.Now,
		Root:          in.Root,
	}

	assets := map[string]Asset{}
	boundaries := map[string]TrustBoundary{}
	usedScenarios := map[string]bool{}
	var hyps []Hypothesis
	grounded := map[string]bool{} // fingerprints that grounded a hypothesis

	// Injection findings → PI-DIRECT + PI-INDIRECT. Dedupe shared sinks the way
	// core/confirm does: two rules pointing at the same handler are one sink.
	type sinkKey struct {
		file string
		line int
		fn   string
	}
	seenSink := map[sinkKey]bool{}
	injection := injectionFindings(in.Findings)
	for i := range injection {
		f := injection[i]
		k := sinkKey{f.Location.FilePath, f.Location.StartLine, f.Metadata["function"]}
		grounded[f.Fingerprint] = true
		if seenSink[k] {
			continue
		}
		seenSink[k] = true

		assets["asset-system-prompt"] = Asset{
			ID:    "asset-system-prompt",
			Kind:  AssetSystemPrompt,
			Label: "the model's confidential system instruction",
		}
		boundaries["bnd-input-model"] = TrustBoundary{
			ID:    "bnd-input-model",
			From:  "untrusted request input",
			To:    "model prompt",
			Label: "untrusted input crosses into the model prompt",
		}
		entry := f.Metadata["route"]
		fpShort := shortID(f.Fingerprint)
		for _, sid := range []string{ScenarioPIDirect, ScenarioPIIndirect} {
			usedScenarios[sid] = true
			h := injectionHypothesis(sid, f, entry, fpShort)
			attachEvidence(&h, f, in)
			hyps = append(hyps, h)
		}
	}

	// Inventory tool matrix → TOOL-UNAUTH and EXFIL-FS-NET.
	if in.Inventory != nil {
		toolHyps, toolAssets, toolBoundaries := toolMatrixHypotheses(in.Inventory.ToolMatrix, usedScenarios)
		hyps = append(hyps, toolHyps...)
		for _, a := range toolAssets {
			assets[a.ID] = a
		}
		for _, b := range toolBoundaries {
			boundaries[b.ID] = b
		}
	}

	// Anything that grounded no hypothesis is skipped with a reason.
	for i := range in.Findings {
		f := in.Findings[i]
		if grounded[f.Fingerprint] {
			continue
		}
		plan.Skipped = append(plan.Skipped, SkipNote{
			Fingerprint: f.Fingerprint,
			RuleID:      f.RuleID,
			Reason:      fmt.Sprintf("no V1 attack scenario maps rule %q", f.RuleID),
		})
	}

	// The plan carries a real attack graph derived from the same evidence, and
	// each hypothesis path becomes a walk over it where one exists. Where the
	// graph has no route, attachGraphPaths leaves the synthesized path in place
	// and says so in the rationale rather than passing a label list off as an
	// observed route.
	plan.Graph = BuildGraph(in.Findings, in.Inventory)
	attachGraphPaths(plan.Graph, hyps)

	plan.Assets = sortedAssets(assets)
	plan.Boundaries = sortedBoundaries(boundaries)
	plan.Scenarios = selectedScenarios(usedScenarios)
	sort.Slice(hyps, func(i, j int) bool { return hyps[i].ID < hyps[j].ID })
	plan.Hypotheses = hyps
	sort.Slice(plan.Skipped, func(i, j int) bool {
		if plan.Skipped[i].Fingerprint != plan.Skipped[j].Fingerprint {
			return plan.Skipped[i].Fingerprint < plan.Skipped[j].Fingerprint
		}
		return plan.Skipped[i].RuleID < plan.Skipped[j].RuleID
	})
	return plan, nil
}

// injectionFindings returns the injection-rule findings sorted deterministically.
func injectionFindings(ff []findings.Finding) []findings.Finding {
	var out []findings.Finding
	for i := range ff {
		if isInjectionRule(ff[i].RuleID) {
			out = append(out, ff[i])
		}
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.Location.FilePath != b.Location.FilePath {
			return a.Location.FilePath < b.Location.FilePath
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
	return out
}

// injectionHypothesis constructs one prompt-injection hypothesis grounded in f.
func injectionHypothesis(scenarioID string, f findings.Finding, entry, fpShort string) Hypothesis {
	scen, _ := ScenarioByID(scenarioID)
	invIDs := make([]string, 0, len(scen.Invariants))
	for _, inv := range scen.Invariants {
		invIDs = append(invIDs, inv.ID)
	}
	path := []PathStep{
		{Kind: StepEntryPoint, ID: "entry", Label: "untrusted request field"},
		{Kind: StepModel, ID: "model", Label: "LLM prompt call"},
		{Kind: StepAsset, ID: "asset-system-prompt", Label: "system instruction"},
	}
	rationale := fmt.Sprintf(
		"%s flagged untrusted input reaching an LLM prompt at %s:%d (function %q); %s tests whether that input can override the model's instruction rather than being treated as data.",
		f.RuleID, f.Location.FilePath, f.Location.StartLine, f.Metadata["function"], scenarioID)
	return Hypothesis{
		ID:                  "hyp-" + scenarioID + "-" + fpShort,
		ScenarioID:          scenarioID,
		Objective:           scen.Objective,
		Rationale:           rationale,
		FindingFingerprints: []string{f.Fingerprint},
		EntryPoint:          entry,
		Path:                path,
		InvariantIDs:        invIDs,
		AttackerInput:       attackerInputOf(f),
		TriggerCondition:    triggerConditionOf(f, scen),
		ExpectedOracle:      scen.Category,
		Assumptions:         assumptionsOf(f, entry),
	}
}

// attachEvidence carries what the scan established onto the hypothesis.
//
// This is the acceptance criterion for Milestone D: given a scan result, `nox
// attack` must be able to consume a hypothesis without rediscovering why nox
// considered it worth testing. The runner previously seeded its ledger with a
// single heuristic claim restating the rationale — a thinner record than the
// scan already held and then threw away.
//
// A caller that supplies neither function gets exactly the old behaviour: an
// empty ledger, no subject, no unknowns. That keeps `nox attack plan` usable
// from a findings file alone, which is how it is used offline.
func attachEvidence(h *Hypothesis, f findings.Finding, in PlanInput) {
	if in.Evidence != nil {
		subject, ledger := in.Evidence(f)
		h.Subject = subject
		h.Evidence = ledger
	}
	if in.Unknowns != nil && !h.Subject.Zero() {
		h.Unknowns = in.Unknowns(h.Subject)
	}
}

// attackerInputOf names the input an attacker would control, from what the
// finding recorded. Empty when the finding does not say — an invented field
// name would read as knowledge.
func attackerInputOf(f findings.Finding) string {
	for _, k := range []string{"source_var", "field", "parameter", "source"} {
		if v := f.Metadata[k]; v != "" {
			return v
		}
	}
	return ""
}

// triggerConditionOf states what would have to hold, in words.
//
// A suspicion, not a constraint. nox records no path constraints at all (see
// docs/research/smt-spike/RESULT.md), so this is what the scenario believes
// rather than something derived, and it says so rather than implying a
// precision it does not have.
func triggerConditionOf(f findings.Finding, scen Scenario) string {
	input := attackerInputOf(f)
	if input == "" {
		input = "the attacker-controlled input"
	}
	return "suspected: " + input + " reaches the " + scen.Category +
		" sink without being neutralised for that context"
}

// assumptionsOf states what the hypothesis takes as true without evidence.
//
// Naming them is what lets a reader disagree with the hypothesis rather than
// only with its result. Every entry here is something nox did NOT establish.
func assumptionsOf(f findings.Finding, entry string) []string {
	out := []string{
		"the entry point " + entry + " is reachable by an attacker",
		"the code path observed statically is the one that executes",
	}
	if f.Metadata["reach_level"] == "" {
		out = append(out, "nothing established that this code is reachable at runtime")
	}
	if lim := f.Metadata["analysis_limitations"]; lim != "" {
		out = append(out, "the analysis of this file was incomplete ("+lim+")")
	}
	return out
}

// toolCapabilities classifies one tool by name and capability tags into whether
// it reads the filesystem, reaches the network, or performs a privileged action.
func toolCapabilities(name string, tags []string) (fs, net, danger bool) {
	hay := strings.ToLower(name + " " + strings.Join(tags, " "))
	contains := func(subs ...string) bool {
		for _, s := range subs {
			if strings.Contains(hay, s) {
				return true
			}
		}
		return false
	}
	fs = contains("file", "read", "fs", "path", "filesystem")
	net = contains("http", "fetch", "url", "post", "request", "network", "webhook", "send")
	danger = contains("shell", "exec", "delete", "admin", "write", "command", "sql")
	return fs, net, danger
}

// toolMatrixHypotheses derives tool-abuse and exfiltration hypotheses from the
// inventory's tool matrix, grounding each in a specific agent/tool set.
func toolMatrixHypotheses(matrix []ai.ToolPermissionSet, used map[string]bool) (hyps []Hypothesis, assets []Asset, boundaries []TrustBoundary) {
	sets := append([]ai.ToolPermissionSet(nil), matrix...)
	sort.Slice(sets, func(i, j int) bool {
		if sets[i].Agent != sets[j].Agent {
			return sets[i].Agent < sets[j].Agent
		}
		return sets[i].Path < sets[j].Path
	})
	for i := range sets {
		set := sets[i]
		var anyFS, anyNet, anyDanger bool
		for _, tool := range set.Tools {
			fs, net, danger := toolCapabilities(tool, set.Capabilities[tool])
			anyFS = anyFS || fs
			anyNet = anyNet || net
			anyDanger = anyDanger || danger
		}
		agentLabel := set.Agent
		if agentLabel == "" {
			agentLabel = set.Server
		}
		idSeed := shortID(agentLabel, set.Path)

		if anyDanger {
			used[ScenarioToolUnauth] = true
			assets = append(assets, Asset{
				ID: "asset-admin-action", Kind: AssetAdminAction,
				Label: "privileged tool action", Attributes: map[string]string{"agent": agentLabel},
			})
			boundaries = append(boundaries, TrustBoundary{
				ID: "bnd-model-tool", From: "model output", To: "tool invocation",
				Label: "model output crosses into a side-effecting tool call",
			})
			hyps = append(hyps, toolHypothesis(ScenarioToolUnauth, agentLabel, set.Path, idSeed))
		}
		if anyFS && anyNet {
			used[ScenarioExfilFSNet] = true
			assets = append(assets,
				Asset{ID: "asset-filesystem", Kind: AssetFilesystem, Label: "readable filesystem", Attributes: map[string]string{"agent": agentLabel}},
				Asset{ID: "asset-network-sink", Kind: AssetNetworkSink, Label: "attacker-reachable network sink"},
			)
			boundaries = append(boundaries, TrustBoundary{
				ID: "bnd-tool-network", From: "filesystem contents", To: "network sink",
				Label: "file contents cross into an outbound network call",
			})
			hyps = append(hyps, toolHypothesis(ScenarioExfilFSNet, agentLabel, set.Path, idSeed))
		}
	}
	return hyps, assets, boundaries
}

// toolHypothesis constructs one tool-abuse or exfiltration hypothesis.
func toolHypothesis(scenarioID, agent, path, idSeed string) Hypothesis {
	scen, _ := ScenarioByID(scenarioID)
	invIDs := make([]string, 0, len(scen.Invariants))
	for _, inv := range scen.Invariants {
		invIDs = append(invIDs, inv.ID)
	}
	var steps []PathStep
	var rationale string
	switch scenarioID {
	case ScenarioToolUnauth:
		steps = []PathStep{
			{Kind: StepEntryPoint, ID: "entry", Label: "untrusted request field"},
			{Kind: StepModel, ID: "model", Label: "LLM prompt call"},
			{Kind: StepAgent, ID: "agent", Label: agent},
			{Kind: StepTool, ID: "tool", Label: "privileged tool"},
		}
		rationale = fmt.Sprintf(
			"agent %q (from %s) exposes a side-effecting tool; %s tests whether untrusted input can coerce that tool's invocation.",
			agent, path, scenarioID)
	case ScenarioExfilFSNet:
		steps = []PathStep{
			{Kind: StepEntryPoint, ID: "entry", Label: "untrusted request field"},
			{Kind: StepModel, ID: "model", Label: "LLM prompt call"},
			{Kind: StepAgent, ID: "agent", Label: agent},
			{Kind: StepTool, ID: "tool-fs", Label: "filesystem-read tool"},
			{Kind: StepSink, ID: "sink", Label: "network sink"},
			{Kind: StepAsset, ID: "asset-filesystem", Label: "file secret"},
		}
		rationale = fmt.Sprintf(
			"agent %q (from %s) can both read files and reach the network; %s tests whether a file secret can be chained to a network sink.",
			agent, path, scenarioID)
	}
	return Hypothesis{
		ID:           "hyp-" + scenarioID + "-" + idSeed,
		ScenarioID:   scenarioID,
		Objective:    scen.Objective,
		Rationale:    rationale,
		EntryPoint:   "",
		Path:         steps,
		InvariantIDs: invIDs,
	}
}

// sortedAssets returns the map's assets sorted by ID.
func sortedAssets(m map[string]Asset) []Asset {
	out := make([]Asset, 0, len(m))
	for _, a := range m {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// sortedBoundaries returns the map's boundaries sorted by ID.
func sortedBoundaries(m map[string]TrustBoundary) []TrustBoundary {
	out := make([]TrustBoundary, 0, len(m))
	for _, b := range m {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// selectedScenarios returns the library scenarios that are in play, sorted by ID.
func selectedScenarios(used map[string]bool) []Scenario {
	var out []Scenario
	for _, s := range Scenarios() {
		if used[s.ID] {
			out = append(out, s)
		}
	}
	return out
}

// JSON returns the plan as pretty-printed JSON.
func (p *Plan) JSON() ([]byte, error) {
	return json.MarshalIndent(p, "", "  ")
}

// LoadPlan parses a plan from JSON.
func LoadPlan(raw []byte) (*Plan, error) {
	var p Plan
	if err := json.Unmarshal(raw, &p); err != nil {
		return nil, fmt.Errorf("attack: parsing plan: %w", err)
	}
	return &p, nil
}
