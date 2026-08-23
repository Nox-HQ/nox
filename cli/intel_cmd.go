package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/evidence"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/intel"
)

const intelUsage = `Usage: nox intel <subcommand> [flags]

  Vulnerability intelligence. Turns scan output into privacy-preserving
  observations, clusters them into candidates with an explicit confidence and
  evidence trail, correlates them with public advisories, and works out what a
  candidate actually means for THIS environment.

    Observe -> Corroborate -> Correlate -> Assess exposure -> Contain

Subcommands:
  observe        turn a scan's findings into observations and record them
  lookup         what does nox know about a package version
  show           the full evidence dossier for one candidate
  exposure       this environment's exposure and blast radius for a candidate
  status         contribution mode and local store summary

  Contribution is OFF by default: nothing leaves your environment unless you
  explicitly choose a sharing mode. nox shares security facts, never customer
  artifacts — no source, no paths, no prompts, no secrets, no customer data.

Run ` + "`nox intel <subcommand> --help`" + ` for the flags of each.
`

// defaultIntelDir is where the local intelligence store lives. It sits under
// the repo so a team can review what their scanner learned, rather than in a
// hidden global cache they never see.
const defaultIntelDir = ".nox/intel"

// runIntel dispatches the intel subcommands.
func runIntel(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, intelUsage)
		return 2
	}
	switch args[0] {
	case "observe":
		return runIntelObserve(args[1:])
	case "lookup":
		return runIntelLookup(args[1:])
	case "show":
		return runIntelShow(args[1:])
	case "exposure":
		return runIntelExposure(args[1:])
	case "status":
		return runIntelStatus(args[1:])
	case "-h", "--help", "help":
		fmt.Print(intelUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown intel subcommand: %s\n", args[0])
		fmt.Fprint(os.Stderr, intelUsage)
		return 2
	}
}

const intelObserveUsage = `Usage: nox intel observe [flags]

  Turn a prior scan's findings into intelligence observations and record them in
  the local store. Offline: this writes to disk and sends nothing.

  An observation is NOT a vulnerability. It is one piece of evidence, with
  provenance, that may or may not corroborate others.

Flags:
  --findings <path>   findings.json from a prior scan (default findings.json)
  --dir <path>        local intelligence store (default .nox/intel)
  --mode <name>       disabled | anonymous | org-private | public-intelligence
                      (default disabled — nothing is prepared for sharing)
  --workspace <name>  workspace label used to derive an opaque reporter id
  --salt <s>          salt for the reporter id; keep it stable and private
  --exploits <path>   attack.trace.json to fold dynamic evidence in
  --dry-run           show what would be recorded, write nothing

Exit: 0 = recorded, 2 = error.
`

func runIntelObserve(args []string) int {
	fs := flag.NewFlagSet("intel observe", flag.ContinueOnError)
	var (
		findingsIn string
		dir        string
		modeName   string
		workspace  string
		salt       string
		exploits   string
		dryRun     bool
	)
	fs.StringVar(&findingsIn, "findings", "findings.json", "findings.json from a prior nox scan")
	fs.StringVar(&dir, "dir", defaultIntelDir, "local intelligence store directory")
	fs.StringVar(&modeName, "mode", string(intel.ModeDisabled), "contribution mode")
	fs.StringVar(&workspace, "workspace", "", "workspace label used to derive an opaque reporter id")
	fs.StringVar(&salt, "salt", "", "salt for the reporter id")
	fs.StringVar(&exploits, "exploits", "", "attack.trace.json to fold dynamic evidence in")
	fs.BoolVar(&dryRun, "dry-run", false, "show what would be recorded, write nothing")
	fs.Usage = func() { fmt.Fprint(os.Stderr, intelObserveUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	mode, err := intel.ParseMode(modeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	found, err := loadFindings(findingsIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	now := time.Now().UTC().Format(time.RFC3339)
	sourceID := intel.SourceID(salt, workspace)
	obs := observationsFrom(found, sourceID, now)
	if len(obs) == 0 {
		fmt.Println("[intel] no findings map to an intelligence observation — nothing recorded")
		return 0
	}

	// Redaction runs even for the purely local store. Keeping one path means the
	// data that would be shared is the same data we hold, so a later decision to
	// contribute cannot accidentally widen what was collected.
	redacted := make([]intel.Observation, 0, len(obs))
	for _, o := range obs {
		r, rerr := intel.Redact(o, mode)
		switch {
		case rerr == nil:
			redacted = append(redacted, r)
		case mode == intel.ModeDisabled:
			// Contribution is off: keep the observation local and unshared.
			redacted = append(redacted, o)
		default:
			fmt.Fprintf(os.Stderr, "warning: dropping an observation: %v\n", rerr)
		}
	}

	cands := intel.Aggregate(redacted, now)

	if exploits != "" {
		n, ierr := foldExploitEvidence(exploits, cands)
		if ierr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", ierr)
		} else if n > 0 {
			fmt.Printf("[intel] folded dynamic exploit evidence into %d candidate(s)\n", n)
		}
	}

	fmt.Printf("[intel] %d observation(s) -> %d candidate(s)   mode=%s\n", len(redacted), len(cands), mode)
	if mode.SharesExternally() {
		fmt.Printf("[intel] mode %q would share security facts only: no source, paths, prompts, secrets, or customer data\n", mode)
	} else {
		fmt.Println("[intel] contribution is off; everything stays in this environment")
	}
	printCandidateTable(cands)

	if dryRun {
		fmt.Println("[intel] --dry-run: nothing written")
		return 0
	}

	store, err := intel.OpenStore(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: opening store %s: %v\n", dir, err)
		return 2
	}
	if err := store.AppendObservations(redacted); err != nil {
		fmt.Fprintf(os.Stderr, "error: recording observations: %v\n", err)
		return 2
	}
	for _, c := range cands {
		if err := store.PutCandidate(c); err != nil {
			fmt.Fprintf(os.Stderr, "error: recording candidate %s: %v\n", c.ID, err)
			return 2
		}
	}
	fmt.Printf("[intel] wrote %s\n", filepath.Clean(dir))
	return 0
}

const intelLookupUsage = `Usage: nox intel lookup <ecosystem>:<package>[@<version>] [flags]

  What does nox know about this package version — from public advisories and
  from local intelligence.

Flags:
  --dir <path>   local intelligence store (default .nox/intel)
  --json         emit JSON

Exit: 0 = nothing known, 1 = at least one candidate at HIGH or above, 2 = error.
`

func runIntelLookup(args []string) int {
	fs := flag.NewFlagSet("intel lookup", flag.ContinueOnError)
	var (
		dir    string
		asJSON bool
	)
	fs.StringVar(&dir, "dir", defaultIntelDir, "local intelligence store directory")
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	fs.Usage = func() { fmt.Fprint(os.Stderr, intelLookupUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "error: a package reference is required, e.g. npm:left-pad@1.3.0")
		fs.Usage()
		return 2
	}
	ecosystem, pkg, version := parsePackageRef(rest[0])
	if pkg == "" {
		fmt.Fprintf(os.Stderr, "error: could not parse %q — use <ecosystem>:<package>[@<version>]\n", rest[0])
		return 2
	}

	store, err := intel.OpenStore(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: opening store %s: %v\n", dir, err)
		return 2
	}
	cands, err := store.Lookup(ecosystem, pkg, version)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: lookup failed: %v\n", err)
		return 2
	}

	// Embargoed and internal candidates must never surface through a general
	// lookup. Filtering here as well as in the store is deliberate: a disclosure
	// leak is not the kind of bug to guard against in exactly one place.
	visible := make([]*intel.Candidate, 0, len(cands))
	for _, c := range cands {
		if c.Disclosure.Discoverable() {
			visible = append(visible, c)
		}
	}

	if asJSON {
		out, merr := json.MarshalIndent(visible, "", "  ")
		if merr != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling: %v\n", merr)
			return 2
		}
		fmt.Println(string(out))
	} else if len(visible) == 0 {
		fmt.Printf("[intel] nothing known about %s:%s%s\n", ecosystem, pkg, versionSuffix(version))
		fmt.Println("[intel] this is an absence of evidence, not evidence of absence")
		return 0
	} else {
		fmt.Printf("[intel] %s:%s%s\n", ecosystem, pkg, versionSuffix(version))
		printCandidateTable(visible)
	}

	for _, c := range visible {
		if c.Confidence().AtLeast(evidence.ConfidenceHigh) {
			return 1
		}
	}
	return 0
}

const intelShowUsage = `Usage: nox intel show <candidate-id> [flags]

  The full evidence dossier for one candidate: every claim, where it came from,
  and how strongly it counts. This is the answer to "why does nox believe this?"

Flags:
  --dir <path>   local intelligence store (default .nox/intel)
  --json         emit JSON

Exit: 0 = shown, 2 = error.
`

func runIntelShow(args []string) int {
	fs := flag.NewFlagSet("intel show", flag.ContinueOnError)
	var (
		dir    string
		asJSON bool
	)
	fs.StringVar(&dir, "dir", defaultIntelDir, "local intelligence store directory")
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	fs.Usage = func() { fmt.Fprint(os.Stderr, intelShowUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "error: a candidate id is required")
		fs.Usage()
		return 2
	}

	store, err := intel.OpenStore(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: opening store %s: %v\n", dir, err)
		return 2
	}
	c, err := store.GetCandidate(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	if asJSON {
		out, merr := json.MarshalIndent(c, "", "  ")
		if merr != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling: %v\n", merr)
			return 2
		}
		fmt.Println(string(out))
		return 0
	}

	fmt.Printf("%s\n", c.ID)
	fmt.Printf("  package       : %s:%s %s\n", c.Ecosystem, c.Package, c.AffectedRange)
	fmt.Printf("  weakness      : %s\n", c.WeaknessClass)
	if c.Summary != "" {
		fmt.Printf("  summary       : %s\n", c.Summary)
	}
	fmt.Printf("  state         : %s\n", c.State)
	fmt.Printf("  disclosure    : %s (discoverable: %v)\n", c.Disclosure, c.Disclosure.Discoverable())
	fmt.Printf("  confidence    : %s\n", c.Confidence())
	fmt.Printf("  observations  : %d from %d independent source(s)\n", c.ObservationCount, c.IndependentSources())
	if len(c.Advisories) > 0 {
		fmt.Printf("  advisories    : %s\n", strings.Join(c.Advisories, ", "))
	} else {
		fmt.Printf("  advisories    : none — no public advisory correlates with this candidate\n")
	}
	fmt.Printf("  first seen    : %s\n", c.FirstObserved)
	fmt.Printf("  last seen     : %s\n", c.LastObserved)

	fmt.Printf("\n  why nox believes this (%d claim(s)):\n", c.Ledger.Len())
	for i := range c.Ledger.Claims {
		cl := c.Ledger.Claims[i]
		marker := " "
		if cl.Kind.Semantic() {
			marker = "~" // an opinion, flagged as one
		} else if cl.Kind.Deterministic() {
			marker = "*"
		}
		fmt.Printf("   %s %-26s w=%-3d %s\n", marker, cl.Kind, cl.Kind.Strength(), cl.Statement)
		if cl.Provenance.Source != "" || cl.Provenance.Reference != "" {
			fmt.Printf("       via %s %s\n", cl.Provenance.Source, cl.Provenance.Reference)
		}
	}
	fmt.Println("\n   * = machine-verified   ~ = model judgment, not machine-verified")
	return 0
}

const intelExposureUsage = `Usage: nox intel exposure <candidate-id> [flags]

  What this candidate means for THIS environment: how far it actually reaches,
  what an attacker gets if they exploit it, and the smallest change that breaks
  the attack path.

  Every rung carries its own evidence. A theoretical path is labelled
  THEORETICAL and is never rendered as a confirmed one.

Flags:
  --dir <path>        local intelligence store (default .nox/intel)
  --components <path> component inventory JSON describing this environment
  --exploits <path>   attack.trace.json to fold dynamic evidence in
  --json              emit JSON

Exit: 0 = assessed, 2 = error.
`

func runIntelExposure(args []string) int {
	fs := flag.NewFlagSet("intel exposure", flag.ContinueOnError)
	var (
		dir        string
		components string
		exploits   string
		asJSON     bool
	)
	fs.StringVar(&dir, "dir", defaultIntelDir, "local intelligence store directory")
	fs.StringVar(&components, "components", "", "component inventory JSON describing this environment")
	fs.StringVar(&exploits, "exploits", "", "attack.trace.json to fold dynamic evidence in")
	fs.BoolVar(&asJSON, "json", false, "emit JSON")
	fs.Usage = func() { fmt.Fprint(os.Stderr, intelExposureUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}
	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(os.Stderr, "error: a candidate id is required")
		fs.Usage()
		return 2
	}

	store, err := intel.OpenStore(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: opening store %s: %v\n", dir, err)
		return 2
	}
	c, err := store.GetCandidate(rest[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	var comps []intel.Component
	if components != "" {
		raw, rerr := os.ReadFile(components)
		if rerr != nil {
			fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", components, rerr)
			return 2
		}
		if uerr := json.Unmarshal(raw, &comps); uerr != nil {
			fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", components, uerr)
			return 2
		}
	}

	var evs []intel.ExploitEvidence
	if exploits != "" {
		loaded, lerr := exploitEvidenceFrom(exploits)
		if lerr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v\n", lerr)
		} else {
			evs = loaded
		}
	}

	exp := intel.Assess(c, comps, evs)

	if asJSON {
		out, merr := json.MarshalIndent(exp, "", "  ")
		if merr != nil {
			fmt.Fprintf(os.Stderr, "error: marshalling: %v\n", merr)
			return 2
		}
		fmt.Println(string(out))
		return 0
	}

	fmt.Printf("%s — exposure in this environment\n", c.ID)
	fmt.Printf("  furthest established reach: %s\n\n", exp.Reach)
	fmt.Printf("  %4d component(s) contain the affected package\n", exp.Present)
	fmt.Printf("  %4d expose the vulnerable path\n", exp.Reachable)
	fmt.Printf("  %4d are externally reachable\n", exp.Exposed)
	fmt.Printf("  %4d are exploitable under this configuration\n", exp.Exploitable)
	fmt.Printf("  %4d confirmed exploitable by a dynamic run\n", exp.Confirmed)

	printBlast("services", exp.Blast.Services)
	printBlast("capabilities", exp.Blast.Capabilities)
	printBlast("identities", exp.Blast.Identities)
	printBlast("data classes", exp.Blast.DataClasses)

	if len(exp.Containment) > 0 {
		fmt.Printf("\n  containment options:\n")
		for _, ct := range exp.Containment {
			fmt.Printf("    [%s] %s\n", ct.Kind, ct.Action)
			fmt.Printf("        %s\n", ct.Rationale)
			fmt.Printf("        projected reach afterwards: %s (projected, not verified)\n", ct.ProjectedReach)
		}
	}
	return 0
}

// printBlast renders one blast-radius dimension. Each item keeps its own reach
// label so a capability an attacker *might* get never reads like one they
// demonstrably do.
func printBlast(label string, items []intel.ReachItem) {
	if len(items) == 0 {
		return
	}
	fmt.Printf("\n  %s reachable after exploitation:\n", label)
	for _, it := range items {
		fmt.Printf("    %-14s %-12s %s\n", it.Reach, it.Name, it.Why)
	}
}

const intelStatusUsage = `Usage: nox intel status [flags]

  Contribution mode and a summary of the local intelligence store.

Flags:
  --dir <path>   local intelligence store (default .nox/intel)
  --mode <name>  the mode to explain (default disabled)

Exit: 0 always (unless the store cannot be read).
`

func runIntelStatus(args []string) int {
	fs := flag.NewFlagSet("intel status", flag.ContinueOnError)
	var (
		dir      string
		modeName string
	)
	fs.StringVar(&dir, "dir", defaultIntelDir, "local intelligence store directory")
	fs.StringVar(&modeName, "mode", string(intel.ModeDisabled), "the mode to explain")
	fs.Usage = func() { fmt.Fprint(os.Stderr, intelStatusUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	mode, err := intel.ParseMode(modeName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	fmt.Printf("contribution mode : %s\n", mode)
	fmt.Printf("  %s\n", mode.Describe())
	fmt.Printf("  shares externally: %v\n", mode.SharesExternally())
	fmt.Printf("\nwhat may ever leave this environment (allowlist, not a filter):\n")
	for _, k := range intel.AllowedAttributeKeys() {
		fmt.Printf("  %s\n", k)
	}
	fmt.Println("\nnever shared: source code, file paths, prompts, credentials, secrets,")
	fmt.Println("file contents, customer data, or raw application traffic.")

	store, err := intel.OpenStore(dir)
	if err != nil {
		fmt.Printf("\nlocal store %s: not initialised\n", dir)
		return 0
	}
	cands, err := store.ListCandidates()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading store: %v\n", err)
		return 2
	}
	obs, err := store.Observations()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading store: %v\n", err)
		return 2
	}
	fmt.Printf("\nlocal store %s: %d candidate(s), %d observation(s)\n", dir, len(cands), len(obs))
	byConfidence := map[evidence.Confidence]int{}
	for _, c := range cands {
		byConfidence[c.Confidence()]++
	}
	for _, lvl := range []evidence.Confidence{
		evidence.ConfidenceConfirmed, evidence.ConfidenceHigh,
		evidence.ConfidenceMedium, evidence.ConfidenceLow,
	} {
		if n := byConfidence[lvl]; n > 0 {
			fmt.Printf("  %-10s %d\n", lvl, n)
		}
	}
	return 0
}

// printCandidateTable renders candidates newest-signal-first, leading with
// confidence and independent-source count. Those two numbers together are what
// stop a loud single reporter from looking like a consensus.
func printCandidateTable(cands []*intel.Candidate) {
	if len(cands) == 0 {
		return
	}
	sorted := make([]*intel.Candidate, len(cands))
	copy(sorted, cands)
	sort.Slice(sorted, func(i, j int) bool {
		ci, cj := sorted[i].Confidence(), sorted[j].Confidence()
		if ci != cj {
			return ci.AtLeast(cj)
		}
		return sorted[i].ID < sorted[j].ID
	})
	fmt.Printf("\n  %-24s %-10s %-6s %-28s %s\n", "CANDIDATE", "CONF", "SRCS", "PACKAGE", "WEAKNESS")
	for _, c := range sorted {
		pkg := c.Package
		if c.Ecosystem != "" {
			pkg = c.Ecosystem + ":" + c.Package
		}
		fmt.Printf("  %-24s %-10s %-6d %-28s %s\n",
			c.ID, c.Confidence(), c.IndependentSources(), truncate(pkg, 28), c.WeaknessClass)
	}
	fmt.Println()
}

// observationsFrom maps scan findings onto intelligence observations. Only
// findings that describe something about a *component* or a recognised weakness
// class become observations — a finding about one line of one private file is
// not intelligence about anything shared, and turning it into an observation
// would be both useless and a privacy risk.
func observationsFrom(fs []findings.Finding, sourceID, now string) []intel.Observation {
	prov := evidence.Provenance{
		Source:     "nox-scan",
		SourceID:   sourceID,
		Tool:       "nox",
		Version:    version,
		ObservedAt: now,
	}
	out := make([]intel.Observation, 0, len(fs))
	for i := range fs {
		f := fs[i]
		class := weaknessClassFor(f)
		if class == "" {
			continue
		}
		o := intel.Observation{
			Ecosystem:     f.Metadata["ecosystem"],
			Package:       f.Metadata["package"],
			Version:       f.Metadata["version"],
			RuleID:        f.RuleID,
			WeaknessClass: class,
			Kind:          evidence.KindHeuristic,
			Provenance:    prov,
			ObservedAt:    now,
			Attributes: map[string]string{
				"severity":   string(f.Severity),
				"confidence": string(f.Confidence),
			},
		}
		// A deterministic analyzer's claim is worth more than a pattern match,
		// and the ledger must be able to tell them apart.
		if f.Confidence == findings.ConfidenceHigh {
			o.Kind = evidence.KindStatic
		}
		o.Fingerprint = intel.Fingerprint(o)
		if err := o.Validate(); err != nil {
			continue
		}
		out = append(out, o)
	}
	return out
}

// weaknessClassFor maps a nox rule id onto the shared weakness vocabulary, or
// "" for findings that are not intelligence about a component.
func weaknessClassFor(f findings.Finding) intel.WeaknessClass {
	id := f.RuleID
	switch {
	case strings.HasPrefix(id, "VULN"):
		return intel.WeaknessClass("known-vulnerable-dependency")
	case strings.HasPrefix(id, "MAL"):
		return intel.WeaknessClass("malicious-package")
	case strings.HasPrefix(id, "AI-PI") || id == "AGENTFLOW-001" || id == "TAINT-AI-001":
		return intel.WeaknessClass("prompt-injection")
	case strings.HasPrefix(id, "AI-TOOL") || strings.HasPrefix(id, "AGENTFLOW"):
		return intel.WeaknessClass("unsafe-tool-exposure")
	default:
		return ""
	}
}

// foldExploitEvidence folds dynamic exploit evidence into matching candidates
// and returns how many were updated.
func foldExploitEvidence(path string, cands []*intel.Candidate) (int, error) {
	evs, err := exploitEvidenceFrom(path)
	if err != nil {
		return 0, err
	}
	n := 0
	for _, ev := range evs {
		for _, c := range cands {
			if intel.IngestExploitEvidence(c, ev) {
				n++
			}
		}
	}
	return n, nil
}

// exploitEvidenceFrom reads an attack.trace.json and projects it onto the
// neutral ExploitEvidence shape. The projection lives here rather than in
// core/intel so the intelligence model stays independent of the attack engine.
func exploitEvidenceFrom(path string) ([]intel.ExploitEvidence, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var doc struct {
		Traces []struct {
			ID             string   `json:"id"`
			Exploitability string   `json:"exploitability"`
			Fingerprints   []string `json:"finding_fingerprints"`
			Ledger         struct {
				Claims []struct {
					Kind string `json:"kind"`
				} `json:"claims"`
			} `json:"ledger"`
			ReproductionHits    int `json:"reproduction_hits"`
			ReproductionSamples int `json:"reproduction_samples"`
		} `json:"traces"`
		GeneratedAt string `json:"generated_at"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	var out []intel.ExploitEvidence
	for _, t := range doc.Traces {
		deterministic := false
		for _, cl := range t.Ledger.Claims {
			if evidence.Kind(cl.Kind).Deterministic() {
				deterministic = true
				break
			}
		}
		ev := intel.ExploitEvidence{
			TraceID:        t.ID,
			Exploitability: evidence.Exploitability(t.Exploitability),
			Deterministic:  deterministic,
			Reproduced:     t.ReproductionSamples > 0 && t.ReproductionHits >= t.ReproductionSamples,
			ObservedAt:     doc.GeneratedAt,
		}
		if len(t.Fingerprints) > 0 {
			for _, fp := range t.Fingerprints {
				e := ev
				e.Fingerprint = fp
				out = append(out, e)
			}
			continue
		}
		out = append(out, ev)
	}
	return out, nil
}

// parsePackageRef splits "<ecosystem>:<package>[@<version>]".
func parsePackageRef(ref string) (ecosystem, pkg, version string) {
	rest := ref
	if i := strings.Index(rest, ":"); i > 0 {
		ecosystem, rest = rest[:i], rest[i+1:]
	}
	// Scoped npm names carry a leading @, so only a LATER @ separates the
	// version. Splitting on the first one would turn @scope/pkg into a version.
	if i := strings.LastIndex(rest, "@"); i > 0 {
		rest, version = rest[:i], rest[i+1:]
	}
	return ecosystem, rest, version
}

// versionSuffix renders "@version" or nothing.
func versionSuffix(v string) string {
	if v == "" {
		return ""
	}
	return "@" + v
}
