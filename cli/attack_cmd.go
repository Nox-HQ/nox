package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/replay"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// Default artifact names for the attack workflow. They sit alongside
// findings.json / ai.inventory.json so a whole verify cycle is file-driven and
// reviewable in a pull request.
const (
	defaultPlanPath   = "attack.plan.json"
	defaultTracePath  = "attack.trace.json"
	defaultSuitePath  = "attack.cases.json"
	defaultReportPath = "attack.regress.json"
)

const attackUsage = `Usage: nox attack <subcommand> [flags]

  Dynamic exploit validation. Turns static AI-security findings into exploit
  hypotheses, safely exercises a RUNNING target, and reports evidence-backed,
  reproducible attack traces.

    Discover -> Analyze -> Hypothesize -> Attack -> Verify -> Reproduce -> Regress

Subcommands:
  plan      build exploit hypotheses from a prior scan (offline, sends nothing)
  run       execute the plan against a target and collect evidence  (ACTIVE)
  replay    re-run one recorded trace and report reproduction        (ACTIVE)
  regress   run recorded attack cases as a security regression suite (ACTIVE)
  mcp       validate an MCP server's tool manifest for poisoning       (ACTIVE)

  ` + "`nox attack plan`" + ` is read-only and offline. Everything else is ACTIVE: it
  sends attack payloads over the network. It is never part of ` + "`nox scan`" + `, never
  runs automatically, and refuses to run without --authorize. nox does NOT run or
  sandbox your target — you point it at a system you own and have isolated.

Run ` + "`nox attack <subcommand> --help`" + ` for the flags of each.
`

// runAttack dispatches the attack subcommands.
func runAttack(args []string) int {
	if len(args) == 0 {
		fmt.Fprint(os.Stderr, attackUsage)
		return 2
	}
	switch args[0] {
	case "plan":
		return runAttackPlan(args[1:])
	case "run":
		return runAttackRun(args[1:])
	case "replay":
		return runAttackReplay(args[1:])
	case "regress":
		return runAttackRegress(args[1:])
	case "mcp":
		return runAttackMCP(args[1:])
	case "-h", "--help", "help":
		fmt.Print(attackUsage)
		return 0
	default:
		fmt.Fprintf(os.Stderr, "unknown attack subcommand: %s\n", args[0])
		fmt.Fprint(os.Stderr, attackUsage)
		return 2
	}
}

const attackPlanUsage = `Usage: nox attack plan [path] [flags]

  Build exploit hypotheses from a prior ` + "`nox scan`" + `. Offline and read-only: it
  reads artifacts and writes a plan. It sends nothing and touches no target.

Flags:
  --findings <path>   findings.json from a prior scan (default findings.json)
  --inventory <path>  ai.inventory.json from a prior scan (default ai.inventory.json)
  --evidence <path>   the evidence artifact a scan was asked to keep; carries
                      what that scan established onto each hypothesis
  --output <path>     write the plan here (default attack.plan.json)
  --json              print the plan as JSON instead of a summary
                      (the plan is written to --output either way)

Exit: 0 = plan written, 2 = error.
`

func runAttackPlan(args []string) int {
	fs := flag.NewFlagSet("attack plan", flag.ContinueOnError)
	var (
		findingsIn  string
		inventoryIn string
		evidenceIn  string
		output      string
		asJSON      bool
	)
	fs.StringVar(&findingsIn, "findings", "findings.json", "findings.json from a prior nox scan")
	fs.StringVar(&inventoryIn, "inventory", "ai.inventory.json", "ai.inventory.json from a prior nox scan")
	fs.StringVar(&evidenceIn, "evidence", "", "the evidence artifact a scan was asked to keep; carries what that scan established onto each hypothesis")
	fs.StringVar(&output, "output", defaultPlanPath, "write the plan here")
	fs.BoolVar(&asJSON, "json", false, "print the plan as JSON instead of a summary")
	fs.Usage = func() { fmt.Fprint(os.Stderr, attackPlanUsage) }
	// parseInterspersed, not fs.Parse: the stdlib flag package stops at the
	// first non-flag token, so `nox attack plan . --output x` would silently
	// drop --output. Every subcommand here takes a positional, so every one
	// needs this.
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}

	root := "."
	if len(positionals) > 0 {
		root = positionals[0]
	}

	found, err := loadFindings(findingsIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// The inventory is optional: without it nox can still hypothesise about
	// prompt-injection entry points, it just cannot reason about tool topology.
	inv, invErr := loadInventory(inventoryIn)
	if invErr != nil {
		fmt.Fprintf(os.Stderr, "warning: %v — tool-abuse and exfiltration scenarios will be skipped\n", invErr)
	}

	// Milestone D's handoff. The evidence a scan gathers lives out-of-band and
	// is discarded when the scan ends, so a plan built from findings.json alone
	// cannot see why nox believed anything. `nox scan --evidence-out` keeps it,
	// and this reads it — the artifact built for replay turns out to be exactly
	// the scan-to-attack handoff.
	//
	// Optional throughout: without it every hypothesis carries an empty ledger,
	// which is the behaviour before this existed and keeps `attack plan` usable
	// from a findings file alone.
	in := attack.PlanInput{
		Root:      root,
		Findings:  found,
		Inventory: inv,
		Now:       time.Now().UTC().Format(time.RFC3339),
	}
	if evidenceIn != "" {
		art, aerr := replay.Load(evidenceIn)
		if aerr != nil {
			fmt.Fprintf(os.Stderr, "warning: %v — hypotheses will carry no evidence\n", aerr)
		} else {
			in.Evidence = evidenceFromArtifact(art)
			in.Unknowns = unknownsFromArtifact(art)
		}
	}
	plan, err := attack.BuildPlan(in)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: building plan: %v\n", err)
		return 2
	}

	raw, err := plan.JSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling plan: %v\n", err)
		return 2
	}
	// --output decides where the plan is written; --json decides what is
	// printed. They are orthogonal, and the write happens either way: a plan
	// that only ever reached stdout cannot be handed to `nox attack run
	// --plan`, and a --json that silently suppressed the artifact made
	// `attack plan --json --output p.json` produce no p.json at all.
	if err := os.WriteFile(output, append(raw, '\n'), 0o644); err != nil { //nolint:gosec // plan artifact, not a secret
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}
	if asJSON {
		fmt.Println(string(raw))
		return 0
	}
	printPlanSummary(plan, output)
	return 0
}

// printPlanSummary renders the plan for a human from the shared PlanView, so the
// CLI and the MCP tool project a plan through exactly the same logic. It leads
// with the rationale for each hypothesis, because a plan the operator cannot
// justify is a plan they should not run.
func printPlanSummary(p *attack.Plan, output string) {
	v := attack.NewPlanView(p)
	fmt.Printf("nox attack plan — %d hypothes%s from %d scenario(s)\n",
		len(v.Hypotheses), plural(len(v.Hypotheses), "is", "es"), v.ScenarioCount)
	fmt.Printf("  assets: %d   trust boundaries: %d\n", v.Assets, v.Boundaries)

	for i := range v.Hypotheses {
		h := v.Hypotheses[i]
		fmt.Printf("\n  %s  [%s]\n", h.ID, h.ScenarioID)
		fmt.Printf("    objective : %s\n", h.Objective)
		fmt.Printf("    why       : %s\n", h.Rationale)
		if h.EntryPoint != "" {
			fmt.Printf("    entry     : %s\n", h.EntryPoint)
		}
		if h.PathArrow != "" {
			fmt.Printf("    path      : %s\n", h.PathArrow)
		}
		if len(h.FindingFingerprints) > 0 {
			fmt.Printf("    findings  : %s\n", strings.Join(h.FindingFingerprints, ", "))
		}
	}

	printSkipped(v.Skipped, v.SkippedTotal)
	fmt.Printf("\n[attack] wrote %s\n", output)
	fmt.Println("[attack] nothing was sent — `nox attack plan` is offline. Use `nox attack run` to execute.")
}

// printSkipped renders the aggregated skip summary. Grouping and ordering are the
// domain's job (attack.AggregateSkips); the only thing that lives here is the
// terminal display cap, which is presentation, not data. The full list is always
// in the plan JSON, so the cap loses nothing.
func printSkipped(skipped []attack.SkipSummary, total int) {
	if len(skipped) == 0 {
		return
	}
	fmt.Printf("\n  not eligible for dynamic validation: %d finding(s) across %d rule(s)\n",
		total, len(skipped))
	shown := skipped
	if len(shown) > skipRulesShown {
		shown = shown[:skipRulesShown]
	}
	for _, s := range shown {
		fmt.Printf("    %-16s x%-5d %s\n", s.RuleID, s.Count, s.Reason)
	}
	if len(skipped) > len(shown) {
		fmt.Printf("    ... and %d more rule(s) — see the `skipped` array in the plan\n",
			len(skipped)-len(shown))
	}
}

// skipRulesShown caps the skip summary. The full list is always in the plan
// JSON, so nothing is lost — this only bounds the terminal output.
const skipRulesShown = 10

// renderPath delegates to the domain so the CLI run-summary renders a path
// exactly as the shared plan view does.
func renderPath(steps []attack.PathStep) string { return attack.RenderPath(steps) }

const attackRunUsage = `Usage: nox attack run [flags]

  Execute an attack plan against a target and collect evidence.

  THIS IS AN ACTIVE CAPABILITY. It sends attack payloads over the network. nox
  does NOT run or sandbox the target: you point it at a system you own and have
  isolated, and you must pass --authorize to acknowledge that.

Flags:
  --plan <path>       attack plan from ` + "`nox attack plan`" + ` (default attack.plan.json)
  --target <url>      base URL of the running target (required unless --profile safe)
  --route <path>      HTTP route to probe, e.g. /chat
  --fields <list>     comma-separated request fields to inject, e.g. persona,message
  --reply-field <k>   JSON key in the response holding the model reply (default reply)
                      name it wrong and nox sees no reply at all, never a defense
  --profile <name>    safe | sandbox | staging | authorized-live (default safe)
  --samples <n>       determinism samples per candidate exploit (default 3)
  --min-hits <k>      min reproductions of n to CONFIRM; k<n for non-deterministic models
  --max-attempts <n>  attempt budget (default 200)
  --max-requests <n>  network request budget (default 500)
  --max-duration <d>  wall-clock budget (default 5m)
  --timeout <d>       per-request HTTP timeout (default 15s)
  --seed <s>          canary seed; the same seed replays identically (default "nox")
  --plant-dir <path>  plant the filesystem canary in this EXISTING directory so
                      exfiltration scenarios can be demonstrated. nox writes one
                      file and removes it when the run ends; it never creates the
                      directory and never overwrites an existing file.
  --output <path>     write the traces here (default attack.trace.json)
  --authorize         REQUIRED for any profile other than safe

Exit: 0 = nothing confirmed, 1 = at least one CONFIRMED exploit, 2 = error.
`

func runAttackRun(args []string) int {
	fs := flag.NewFlagSet("attack run", flag.ContinueOnError)
	var (
		planPath    string
		target      string
		route       string
		fieldsCSV   string
		replyField  string
		profileName string
		samples     int
		minHits     int
		maxAttempts int
		maxRequests int
		maxDuration time.Duration
		timeout     time.Duration
		seed        string
		plantDir    string
		output      string
		authorize   bool
	)
	fs.StringVar(&planPath, "plan", defaultPlanPath, "attack plan produced by `nox attack plan`")
	fs.StringVar(&target, "target", "", "base URL of the running target")
	fs.StringVar(&route, "route", "", "HTTP route to probe (e.g. /chat)")
	fs.StringVar(&fieldsCSV, "fields", "", "comma-separated request fields to inject")
	fs.StringVar(&replyField, "reply-field", "reply", "JSON key in the response holding the model reply")
	fs.StringVar(&profileName, "profile", string(attack.ProfileSafe), "safety profile")
	fs.IntVar(&samples, "samples", 3, "determinism samples per candidate exploit")
	fs.IntVar(&minHits, "min-hits", 0, "min reproductions of samples to CONFIRM (default = samples)")
	fs.IntVar(&maxAttempts, "max-attempts", 0, "attempt budget")
	fs.IntVar(&maxRequests, "max-requests", 0, "network request budget")
	fs.DurationVar(&maxDuration, "max-duration", 0, "wall-clock budget")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request HTTP timeout")
	fs.StringVar(&seed, "seed", "nox", "canary seed; the same seed replays identically")
	fs.StringVar(&plantDir, "plant-dir", "", "existing directory to plant the filesystem canary in")
	fs.StringVar(&output, "output", defaultTracePath, "write the traces here")
	fs.BoolVar(&authorize, "authorize", false, "acknowledge you are authorized to attack --target")
	fs.Usage = func() { fmt.Fprint(os.Stderr, attackRunUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	profile, err := attack.ParseProfile(profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}

	// Refuse loudly and early. The check is duplicated inside core/attack — this
	// one exists to give the operator a usable message instead of an error type.
	if profile.RequiresAuthorization() && !authorize {
		fmt.Fprintf(os.Stderr, "error: profile %q is ACTIVE — it fires attack payloads at --target.\n", profile)
		fmt.Fprintln(os.Stderr, "Pass --authorize to confirm you own and have isolated the target. Refusing to run.")
		return 2
	}
	if profile.AllowsNetwork() && target == "" {
		fmt.Fprintf(os.Stderr, "error: --target is required for profile %q\n", profile)
		return 2
	}

	planRaw, err := os.ReadFile(planPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v (run `nox attack plan` first)\n", planPath, err)
		return 2
	}
	plan, err := attack.LoadPlan(planRaw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", planPath, err)
		return 2
	}

	cfg := attack.RunConfig{
		Profile:    profile,
		Authorized: authorize,
		Budget:     budgetFrom(maxAttempts, maxRequests, maxDuration),
		Samples:    samples,
		MinHits:    minHits,
		Seed:       seed,
		Now:        time.Now().UTC().Format(time.RFC3339),
		Route:      route,
		Fields:     splitCSV(fieldsCSV),
		// The engine is pure by design; the CLI is where a real clock belongs,
		// and without one --max-duration would be a flag that does nothing.
		Clock: time.Now,
	}

	// Planting writes into the environment under test, so it happens here at the
	// edge rather than inside the engine, and only when the operator names a
	// directory. Cleanup is deferred before the error is checked: Plant always
	// returns a usable cleanup, and a canary left behind is a fake secret
	// sitting in someone's filesystem.
	planted, cleanup, plantErr := plantCanaries(plan, seed, plantDir, profile, authorize)
	defer func() {
		if err := cleanup(); err != nil {
			fmt.Fprintf(os.Stderr, "warning: %v — remove it by hand\n", err)
		}
	}()
	if plantErr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", plantErr)
		return 2
	}
	for _, pc := range planted {
		fmt.Printf("[attack] planted canary %s at %s (removed when this run ends)\n", pc.Canary.ID, pc.Path)
	}

	tgt := targetFor(profile, target, replyField, timeout)

	if profile.AllowsNetwork() {
		fmt.Printf("nox attack run — ACTIVE, profile=%s, target=%s\n", profile, target)
		fmt.Println("  (nox is not sandboxing this target; you are responsible for isolating it)")
	} else {
		fmt.Printf("nox attack run — profile=safe: simulating %d hypothes%s, sending nothing\n",
			len(plan.Hypotheses), plural(len(plan.Hypotheses), "is", "es"))
	}

	res, err := attack.Run(context.Background(), plan, tgt, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: attack run failed: %v\n", err)
		return 2
	}

	raw, err := res.JSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling result: %v\n", err)
		return 2
	}
	if err := os.WriteFile(output, append(raw, '\n'), 0o644); err != nil { //nolint:gosec // trace artifact, not a secret
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}

	printRunSummary(res, output)
	return res.ExitCode()
}

// printRunSummary renders traces. Every verdict is printed with the wording
// core/evidence fixes for it, so no surface of nox ever softens INCONCLUSIVE
// into "clean" or PREVENTED into "safe".
func printRunSummary(r *attack.Result, output string) {
	if len(r.Traces) == 0 {
		fmt.Println("[attack] no hypotheses in the plan — nothing to attempt")
		fmt.Printf("[attack] wrote %s\n", output)
		return
	}
	if !r.ControlSound {
		fmt.Println("\n  !! the benign control tripped a hijack signal: this environment cannot")
		fmt.Println("     distinguish obedience from noise, so NOTHING was confirmed.")
	}

	counts := map[evidence.Exploitability]int{}
	for i := range r.Traces {
		t := r.Traces[i]
		counts[t.Exploitability]++

		fmt.Printf("\n  %s  [%s]  %s\n", t.ID, t.ScenarioID, t.Exploitability)
		fmt.Printf("    objective : %s\n", t.Objective)
		fmt.Printf("    reading   : %s\n", evidence.Describe(t.Exploitability))
		if path := renderPath(t.Path); path != "" {
			fmt.Printf("    path      : %s\n", path)
		}
		if t.Evidence != nil {
			ev := t.Evidence
			fmt.Printf("    oracle    : %s (%s)\n", ev.OracleName, ev.OracleKind)
			fmt.Printf("    signal    : %s\n", ev.Signal)
			if ev.Field != "" {
				fmt.Printf("    entered   : field %q via payload %s\n", ev.Field, ev.PayloadID)
			}
			fmt.Printf("    response  : %s\n", truncate(ev.Response, 160))
		}
		// Only report reproduction for a trace that actually ran. Printing
		// "0 / 3 attempts" for a simulated trace would claim three failed
		// attempts where none were made — the exact overstatement the
		// exploitability ladder exists to prevent.
		if t.Outcome.Executed && t.ReproductionSamples > 0 {
			fmt.Printf("    reproduced: %d / %d attempts\n", t.ReproductionHits, t.ReproductionSamples)
		}
		fmt.Printf("    confidence: %s", t.Confidence)
		if t.Ledger.HasSemantic() {
			fmt.Print("  (includes a semantic judgment — not machine-verified)")
		}
		fmt.Println()
		if t.Exploitability == evidence.Confirmed {
			fmt.Printf("    replay    : %s\n", t.ReplayCommand)
		}
		if t.Note != "" {
			fmt.Printf("    note      : %s\n", t.Note)
		}
	}

	fmt.Printf("\n  summary: %d confirmed, %d prevented, %d inconclusive, %d plausible, %d potential\n",
		counts[evidence.Confirmed], counts[evidence.Prevented], counts[evidence.Inconclusive],
		counts[evidence.Plausible], counts[evidence.Potential])
	if r.BudgetStop != "" {
		fmt.Printf("  stopped early: %s (affected traces are INCONCLUSIVE, not prevented)\n", r.BudgetStop)
	}

	// The verification-effort metric: hypotheses resolved per probe, not
	// coverage. A run that fired many probes and decided nothing reads worse
	// here than a small run that decided something, which is the comparison a
	// coverage number cannot make.
	e := r.Efficiency()
	fmt.Printf("  resolved %d of %d hypotheses in %d attempt(s)", e.Resolved, e.Hypotheses, e.Attempts)
	if e.Resolved > 0 {
		fmt.Printf(" — %.1f attempts per resolution", e.AttemptsPerResolution())
	} else {
		fmt.Print(" — this run decided nothing")
	}
	fmt.Println()

	fmt.Printf("[attack] wrote %s\n", output)
}

const attackReplayUsage = `Usage: nox attack replay <trace-id> [flags]

  Re-run one recorded attack trace against a target and report whether it still
  reproduces. ACTIVE: it sends the recorded payload again.

Flags:
  --trace <path>      traces from ` + "`nox attack run`" + ` (default attack.trace.json)
  --target <url>      base URL of the running target (required)
  --route <path>      HTTP route to probe; defaults to the route recorded in the trace
  --fields <list>     comma-separated request fields; defaults to those recorded
  --reply-field <k>   JSON key in the response holding the model reply (default reply)
                      name it wrong and nox sees no reply at all, never a defense
  --profile <name>    sandbox | staging | authorized-live (default sandbox)
  --samples <n>       determinism samples (default 3)
  --min-hits <k>      min reproductions of samples to CONFIRM (default = samples)
  --timeout <d>       per-request HTTP timeout (default 15s)
  --seed <s>          canary seed; must match the original run (default "nox")
  --authorize         REQUIRED

Exit: 0 = did not reproduce, 1 = reproduced (still exploitable), 2 = error.
`

func runAttackReplay(args []string) int {
	fs := flag.NewFlagSet("attack replay", flag.ContinueOnError)
	var (
		tracePath   string
		target      string
		route       string
		fieldsCSV   string
		replyField  string
		profileName string
		samples     int
		minHits     int
		timeout     time.Duration
		seed        string
		authorize   bool
	)
	fs.StringVar(&tracePath, "trace", defaultTracePath, "traces from `nox attack run`")
	fs.StringVar(&target, "target", "", "base URL of the running target")
	fs.StringVar(&route, "route", "", "HTTP route to probe (defaults to the recorded route)")
	fs.StringVar(&fieldsCSV, "fields", "", "comma-separated request fields (defaults to those recorded)")
	fs.StringVar(&replyField, "reply-field", "reply", "JSON key in the response holding the model reply")
	fs.StringVar(&profileName, "profile", string(attack.ProfileSandbox), "safety profile")
	fs.IntVar(&samples, "samples", 3, "determinism samples")
	fs.IntVar(&minHits, "min-hits", 0, "min reproductions of samples to CONFIRM (default = samples)")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request HTTP timeout")
	fs.StringVar(&seed, "seed", "nox", "canary seed; must match the original run")
	fs.BoolVar(&authorize, "authorize", false, "acknowledge you are authorized to attack --target")
	fs.Usage = func() { fmt.Fprint(os.Stderr, attackReplayUsage) }
	positionals, err := parseInterspersed(fs, args)
	if err != nil {
		return 2
	}
	if len(positionals) == 0 {
		fmt.Fprintln(os.Stderr, "error: a trace id is required")
		fs.Usage()
		return 2
	}
	traceID := positionals[0]

	profile, perr := attack.ParseProfile(profileName)
	if perr != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", perr)
		return 2
	}
	if profile.RequiresAuthorization() && !authorize {
		fmt.Fprintln(os.Stderr, "error: replay is ACTIVE — it re-sends the recorded attack payload.")
		fmt.Fprintln(os.Stderr, "Pass --authorize to confirm you own and have isolated the target. Refusing to run.")
		return 2
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		return 2
	}

	raw, err := os.ReadFile(tracePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", tracePath, err)
		return 2
	}
	res, err := attack.LoadResult(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", tracePath, err)
		return 2
	}

	// Fall back to the entry point the original run recorded. Without this the
	// replay probes the base URL, every request 404s, and "did not reproduce"
	// would look like a fix that held.
	if route == "" {
		route = res.Route
	}
	fields := splitCSV(fieldsCSV)
	if len(fields) == 0 {
		fields = res.Fields
	}

	cfg := attack.RunConfig{
		Profile:    profile,
		Authorized: authorize,
		Samples:    samples,
		MinHits:    minHits,
		Seed:       seed,
		Now:        time.Now().UTC().Format(time.RFC3339),
		Route:      route,
		Fields:     fields,
		// No Budget/Clock: Replay is bounded by --samples (it re-fires one
		// recorded probe that many times) and by the per-request --timeout, and
		// it exposes no --max-duration. Carrying a budget nothing reads would be
		// an inert control implying enforcement that does not exist.
	}

	fmt.Printf("nox attack replay %s — ACTIVE against %s%s\n", traceID, target, route)
	t, err := attack.Replay(context.Background(), res, traceID,
		targetFor(profile, target, replyField, timeout), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: replay failed: %v\n", err)
		return 2
	}

	fmt.Printf("\n  %s  [%s]  %s\n", t.ID, t.ScenarioID, t.Exploitability)
	fmt.Printf("    reading   : %s\n", evidence.Describe(t.Exploitability))
	if t.Outcome.Executed && t.ReproductionSamples > 0 {
		fmt.Printf("    reproduced: %d / %d attempts\n", t.ReproductionHits, t.ReproductionSamples)
	}
	if t.Exploitability == evidence.Confirmed {
		return 1
	}
	return 0
}

const attackRegressUsage = `Usage: nox attack regress [flags]

  Run recorded attack cases as a security regression suite. A confirmed exploit
  becomes a permanent test: after you fix it, this proves it stays fixed.

  Because model behaviour is not deterministic, cases pass a k-of-n threshold
  rather than an exact match.

Flags:
  --record            derive a case suite from --trace and write --suite, then exit
  --trace <path>      traces from ` + "`nox attack run`" + ` (default attack.trace.json)
  --suite <path>      the case suite (default attack.cases.json)
  --target <url>      base URL of the running target (required unless --record)
  --route <path>      HTTP route to probe; defaults to the route recorded per case
  --fields <list>     comma-separated request fields; defaults to those recorded
  --reply-field <k>   JSON key in the response holding the model reply (default reply)
                      name it wrong and nox sees no reply at all, never a defense
  --profile <name>    sandbox | staging | authorized-live (default sandbox)
  --timeout <d>       per-request HTTP timeout (default 15s)
  --seed <s>          canary seed; must match the original run (default "nox")
  --output <path>     write the suite result here (default attack.regress.json)
  --authorize         REQUIRED unless --record

Exit: 0 = no regressions, 1 = a previously fixed exploit reproduced,
      2 = error, or the target could not be exercised at all (nothing proven).
`

func runAttackRegress(args []string) int {
	fs := flag.NewFlagSet("attack regress", flag.ContinueOnError)
	var (
		record      bool
		tracePath   string
		suitePath   string
		target      string
		route       string
		fieldsCSV   string
		replyField  string
		profileName string
		timeout     time.Duration
		seed        string
		output      string
		authorize   bool
	)
	fs.BoolVar(&record, "record", false, "derive a case suite from --trace and exit")
	fs.StringVar(&tracePath, "trace", defaultTracePath, "traces from `nox attack run`")
	fs.StringVar(&suitePath, "suite", defaultSuitePath, "the case suite")
	fs.StringVar(&target, "target", "", "base URL of the running target")
	fs.StringVar(&route, "route", "", "HTTP route to probe (defaults to each case's recorded route)")
	fs.StringVar(&fieldsCSV, "fields", "", "comma-separated request fields (defaults to those recorded)")
	fs.StringVar(&replyField, "reply-field", "reply", "JSON key in the response holding the model reply")
	fs.StringVar(&profileName, "profile", string(attack.ProfileSandbox), "safety profile")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request HTTP timeout")
	fs.StringVar(&seed, "seed", "nox", "canary seed; must match the original run")
	fs.StringVar(&output, "output", defaultReportPath, "write the suite result here")
	fs.BoolVar(&authorize, "authorize", false, "acknowledge you are authorized to attack --target")
	fs.Usage = func() { fmt.Fprint(os.Stderr, attackRegressUsage) }
	if err := fs.Parse(args); err != nil {
		return 2
	}

	if record {
		return recordAttackSuite(tracePath, suitePath)
	}

	profile, err := attack.ParseProfile(profileName)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if profile.RequiresAuthorization() && !authorize {
		fmt.Fprintln(os.Stderr, "error: regress is ACTIVE — it re-sends recorded attack payloads.")
		fmt.Fprintln(os.Stderr, "Pass --authorize to confirm you own and have isolated the target. Refusing to run.")
		return 2
	}
	if target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required (or pass --record to only write the suite)")
		return 2
	}

	raw, err := os.ReadFile(suitePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v (run `nox attack regress --record` first)\n", suitePath, err)
		return 2
	}
	suite, err := attack.LoadSuite(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", suitePath, err)
		return 2
	}

	cfg := attack.RunConfig{
		Profile:    profile,
		Authorized: authorize,
		Seed:       seed,
		Now:        time.Now().UTC().Format(time.RFC3339),
		Route:      route,
		Fields:     splitCSV(fieldsCSV),
		// No Budget/Clock — see runAttackReplay. A suite is bounded by each
		// case's recorded sample count and the per-request --timeout.
	}

	fmt.Printf("nox attack regress — %d case(s), ACTIVE against %s\n", len(suite.Cases), target)
	sr, err := attack.RunSuite(context.Background(), suite,
		targetFor(profile, target, replyField, timeout), cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: regression run failed: %v\n", err)
		return 2
	}

	out, err := json.MarshalIndent(sr, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling result: %v\n", err)
		return 2
	}
	if err := os.WriteFile(output, append(out, '\n'), 0o644); err != nil { //nolint:gosec // report artifact, not a secret
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}

	// The suite reads as a test suite: the outcome column is the pass/fail CI
	// gates on. The evidence claim is a separate, quieter annotation, because
	// "the recorded payload no longer reproduces" and "the target is secure"
	// are different statements and only the first one was demonstrated.
	for i := range sr.Results {
		c := sr.Results[i]
		fmt.Printf("  %-11s %-34s %d/%d hits\n", c.Outcome, c.Case.ID, c.Hits, c.Samples)
		fmt.Printf("              claim: %s — %s\n", c.Exploitability, evidence.Describe(c.Exploitability))
		if c.Note != "" {
			fmt.Printf("              %s\n", c.Note)
		}
	}
	fmt.Printf("\n  %d held, %d regression(s), %d unexercised\n",
		len(sr.Results)-sr.Regressions-sr.Unexercised, sr.Regressions, sr.Unexercised)
	if sr.Unexercised > 0 {
		fmt.Printf("  !! %d case(s) never reached the target. Zero regressions here means the\n", sr.Unexercised)
		fmt.Printf("     suite proved nothing, not that the fixes held. Check --target and --route.\n")
	}
	fmt.Printf("[attack] wrote %s\n", output)
	return sr.ExitCode()
}

// recordAttackSuite turns a completed run into a persistent regression suite.
// Only confirmed exploits become cases: an inconclusive attempt is not a
// security guarantee and must not be enshrined as one.
func recordAttackSuite(tracePath, suitePath string) int {
	raw, err := os.ReadFile(tracePath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", tracePath, err)
		return 2
	}
	res, err := attack.LoadResult(raw)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: parsing %s: %v\n", tracePath, err)
		return 2
	}
	suite := attack.SuiteFromResult(res, time.Now().UTC().Format(time.RFC3339))
	out, err := suite.JSON()
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling suite: %v\n", err)
		return 2
	}
	if err := os.WriteFile(suitePath, append(out, '\n'), 0o644); err != nil { //nolint:gosec // suite artifact, not a secret
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", suitePath, err)
		return 2
	}
	fmt.Printf("[attack] recorded %d case(s) to %s\n", len(suite.Cases), suitePath)
	if len(suite.Cases) == 0 {
		fmt.Println("[attack] no CONFIRMED exploits in the trace — an unconfirmed attempt is not a regression test")
	}
	return 0
}

// plantCanaries plants the filesystem canary when the operator asked for it,
// and otherwise says plainly why an exfiltration scenario cannot be
// demonstrated.
//
// That second half matters as much as the first. Without a planted canary the
// EXFIL scenario has nothing to exfiltrate, so it can only ever come back
// INCONCLUSIVE — and an INCONCLUSIVE with no stated cause reads like the target
// was tested and found clean. Naming the reason is the difference between "we
// could not test this" and a silent false all-clear.
func plantCanaries(plan *attack.Plan, seed, dir string, profile attack.Profile, authorized bool) ([]attack.PlantedCanary, attack.CleanupFunc, error) {
	noop := func() error { return nil }
	needs := planNeedsFilesystemCanary(plan)

	if dir == "" {
		if needs && profile.AllowsNetwork() {
			fmt.Println("[attack] note: this plan contains an exfiltration scenario, but no --plant-dir was given.")
			fmt.Println("         nox has planted no canary, so there is nothing for the target to exfiltrate and")
			fmt.Println("         the scenario CANNOT be confirmed. Its verdict will be INCONCLUSIVE because the")
			fmt.Println("         test could not be performed — not because the target resisted it.")
		}
		return nil, noop, nil
	}
	if !needs {
		fmt.Println("[attack] note: --plant-dir was given but no scenario in this plan uses a filesystem canary; nothing planted.")
		return nil, noop, nil
	}
	return attack.Plant(attack.MintCanaries(seed), dir, profile, authorized)
}

// planNeedsFilesystemCanary reports whether any hypothesis relies on a planted
// file to be demonstrable.
func planNeedsFilesystemCanary(plan *attack.Plan) bool {
	if plan == nil {
		return false
	}
	for i := range plan.Hypotheses {
		if plan.Hypotheses[i].ScenarioID == attack.ScenarioExfilFSNet {
			return true
		}
	}
	return false
}

// targetFor picks the adapter for a profile. The safe profile gets a target
// that physically cannot reach the network, so "safe" is a property of the
// wiring rather than a promise in the docs.
func targetFor(p attack.Profile, base, replyField string, timeout time.Duration) attack.Target {
	if !p.AllowsNetwork() {
		return attack.NewSimTarget()
	}
	return attack.NewHTTPTarget(base, replyField, timeout)
}

// budgetFrom overlays any explicitly supplied limits on the defaults, so a
// caller can raise one budget without having to restate the rest.
func budgetFrom(attempts, requests int, duration time.Duration) attack.Budget {
	b := attack.DefaultBudget()
	if attempts > 0 {
		b.Attempts = attempts
	}
	if requests > 0 {
		b.NetworkRequests = requests
	}
	if duration > 0 {
		b.Duration = duration
	}
	return b
}

// loadFindings reads a findings.json emitted by `nox scan`, via the one shared
// report loader, adding the CLI's "run scan first" hint on a read error.
func loadFindings(path string) ([]findings.Finding, error) {
	ff, err := report.LoadFindingsFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w (run `nox scan` first)", path, err)
	}
	return ff, nil
}

// loadInventory reads an ai.inventory.json emitted by `nox scan`.
func loadInventory(path string) (*ai.Inventory, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	var inv ai.Inventory
	if err := json.Unmarshal(data, &inv); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &inv, nil
}

// plural picks a suffix for n.
func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// evidenceFromArtifact adapts a Track I evidence artifact into the lookup
// BuildPlan wants: given a finding, the subject its claims were filed against
// and the ledger of those claims.
//
// The artifact records verdicts by fingerprint and claims by subject, so the
// join is fingerprint → subject → ledger. A finding the artifact does not know
// yields the zero subject and an empty ledger, which is honest: this scan
// established nothing about it.
func evidenceFromArtifact(a *replay.Artifact) func(findings.Finding) (evidence.Subject, evidence.Ledger) {
	bySubject := make(map[string]evidence.Subject, len(a.Findings))
	for _, v := range a.Findings {
		bySubject[v.Fingerprint] = v.Subject
	}
	return func(f findings.Finding) (evidence.Subject, evidence.Ledger) {
		s, ok := bySubject[f.Fingerprint]
		if !ok {
			return evidence.Subject{}, evidence.Ledger{}
		}
		l, _ := a.LedgerFor(s)
		return s, l
	}
}

// unknownsFromArtifact reports the questions the scan left open, cheapest
// first, from the capability state it recorded.
//
// A capability that answered nothing is an open question whether or not
// anything provides it, and both are worth carrying: one tells the reader what
// to install, the other tells them what to run. The order is the artifact's,
// which is capability.All()'s — the same cheapest-first ordering
// adjudicate.MissingEvidence uses.
func unknownsFromArtifact(a *replay.Artifact) func(evidence.Subject) []string {
	var open []string
	for _, c := range a.Capabilities {
		if c.Answered > 0 {
			continue
		}
		switch {
		case !c.Provided:
			open = append(open, c.Capability+": nothing on that installation could establish it")
		case c.Inconclusive > 0:
			open = append(open, c.Capability+": ran and could not determine anything")
		default:
			open = append(open, c.Capability+": nothing in that scan put the question")
		}
	}
	// Scan-wide rather than per-subject: the artifact records capability counts
	// across the scan, not per finding. Saying so beats inventing a per-subject
	// breakdown the artifact cannot support.
	return func(evidence.Subject) []string { return open }
}
