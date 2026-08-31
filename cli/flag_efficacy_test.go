package main

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/findings"
)

// This file exists because a flag that parses, is stored, and then does nothing
// is worse than a missing flag. `nox attack run --max-duration` did exactly
// that: it was parsed, carried on the Budget, and compared against an elapsed
// time nothing ever set — an operator capping a live attack at two minutes got
// an unbounded run and a report that looked like the cap had held. A security
// control that reports success while not working is the failure mode this whole
// command is supposed to detect in other people's systems.
//
// So every guard below asserts a flag CHANGES AN OBSERVABLE OUTCOME, and the
// inventory at the bottom refuses to let a documented flag exist without either
// such a guard or an explicit note saying it is informational. Coverage is
// deliberately concentrated on `nox attack`, the one ACTIVE surface where an
// inert flag means unintended traffic.

// captureCLI runs a command entry point with stdout and stderr redirected,
// returning its exit code and everything it printed. Commands report refusals on
// stderr and progress on stdout; a guard about a refusal has to read both.
func captureCLI(t *testing.T, fn func() int) (exitCode int, output string) {
	t.Helper()
	origOut, origErr := os.Stdout, os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("pipe: %v", err)
	}
	os.Stdout, os.Stderr = w, w
	done := make(chan string, 1)
	go func() {
		var buf bytes.Buffer
		_, _ = io.Copy(&buf, r)
		done <- buf.String()
	}()
	code := fn()
	_ = w.Close()
	os.Stdout, os.Stderr = origOut, origErr
	return code, <-done
}

// TestAttackMCPRefusesWithoutAuthorize completes the set that
// TestActiveSubcommandsRefuseWithoutAuthorization covers for run/replay/regress.
// `attack mcp` is ACTIVE for a reason that is easy to overlook because it sends
// no payload: capturing a manifest SPAWNS the server's subprocess, or dials it.
// Running a stranger's MCP server is the act being authorized.
func TestAttackMCPRefusesWithoutAuthorize(t *testing.T) {
	transports := []struct {
		name string
		args []string
	}{
		{"stdio", []string{"--command", "nox-attack-mcp-should-never-run"}},
		{"http", []string{"--url", "http://127.0.0.1:1"}},
		{"grpc", []string{"--addr", "127.0.0.1:1"}},
	}
	for _, tr := range transports {
		t.Run(tr.name, func(t *testing.T) {
			code, out := captureCLI(t, func() int { return runAttackMCP(tr.args) })
			if code != 2 {
				t.Errorf("nox attack mcp --%s without --authorize exited %d, want 2 (refusal)", tr.name, code)
			}
			if !strings.Contains(out, "--authorize") {
				t.Errorf("the refusal must name the flag that lifts it; got: %s", out)
			}
		})
	}
}

// attackPlanFile writes a plan grounded in one injection finding and returns its
// path. Two hypotheses (direct and indirect prompt injection) is enough for a
// run to fire probes, which is all the budget guards need.
func attackPlanFile(t *testing.T, dir string) string {
	t.Helper()
	plan, err := attack.BuildPlan(attack.PlanInput{
		Root: dir,
		Findings: []findings.Finding{{
			RuleID:      "AGENTFLOW-001",
			Fingerprint: "fp-flag-efficacy",
			Severity:    findings.SeverityHigh,
			Confidence:  findings.ConfidenceHigh,
			Location:    findings.Location{FilePath: "app/handlers.py", StartLine: 42},
			Message:     "untrusted input reaches an LLM prompt",
			Metadata:    map[string]string{"function": "chat", "route": "/chat"},
		}},
		Now: "2026-08-23T00:00:00Z",
	})
	if err != nil {
		t.Fatalf("building the plan: %v", err)
	}
	if len(plan.Hypotheses) == 0 {
		t.Fatal("the fixture plan has no hypotheses; the budget guards would be vacuous")
	}
	raw, err := plan.JSON()
	if err != nil {
		t.Fatalf("marshalling the plan: %v", err)
	}
	path := filepath.Join(dir, "attack.plan.json")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatalf("writing the plan: %v", err)
	}
	return path
}

// TestAttackRunMaxDurationStopsTheRun is the regression guard for the bug this
// file was written around. It drives the real `nox attack run` entry point
// against a local target twice — once unbounded, once with a wall-clock budget
// that is already spent — and reads the traces the CLI wrote. The flag must
// change what the run DID: no probe fired, and the trace naming the budget that
// stopped it. Asserting only that the value reaches the Budget is what let the
// original bug ship.
func TestAttackRunMaxDurationStopsTheRun(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"reply":"I cannot help with that."}`))
	}))
	defer srv.Close()

	dir := t.TempDir()
	planPath := attackPlanFile(t, dir)

	runTo := func(out string, extra ...string) *attack.Result {
		t.Helper()
		args := append([]string{
			"--plan", planPath,
			"--target", srv.URL,
			"--route", "/chat",
			"--profile", "sandbox",
			"--authorize",
			"--samples", "1",
			"--output", out,
		}, extra...)
		code, printed := captureCLI(t, func() int { return runAttackRun(args) })
		if code == 2 {
			t.Fatalf("attack run failed: %s", printed)
		}
		raw, err := os.ReadFile(out) //nolint:gosec // path built by this test
		if err != nil {
			t.Fatalf("--output %s was not written: %v", out, err)
		}
		res, err := attack.LoadResult(raw)
		if err != nil {
			t.Fatalf("parsing traces: %v", err)
		}
		return res
	}

	unbounded := runTo(filepath.Join(dir, "unbounded.json"))
	if unbounded.BudgetStop != "" {
		t.Fatalf("the control run stopped on %q; it must run to completion for the comparison to mean anything", unbounded.BudgetStop)
	}
	if unbounded.Spend.Attempts == 0 {
		t.Fatal("the control run fired no probes; the budget guard below would pass vacuously")
	}

	// A 1ns budget is spent as soon as the clock advances at all, so a
	// --max-duration that reaches a real clock stops the run almost immediately.
	//
	// "Almost" is the operative word, and the reason this does not assert zero
	// probes. Budget exhaustion is `elapsed >= duration`, and clock granularity
	// is platform-dependent: on Windows the first reading can still be exactly
	// zero, so one probe slips through before the clock ticks. That is a
	// property of the host clock, not of the flag, and pinning it to zero made
	// this guard fail on Windows for a reason that says nothing about whether
	// --max-duration works.
	//
	// What must hold everywhere: the run stops FOR THE DURATION REASON, and
	// does markedly less work than the unbounded control. A flag that did
	// nothing would leave budget_stop empty and the attempt count unchanged, so
	// the guard still bites.
	capped := runTo(filepath.Join(dir, "capped.json"), "--max-duration", "1ns")
	if capped.BudgetStop != "duration" {
		t.Errorf("--max-duration 1ns produced budget_stop %q, want \"duration\" — the flag is not being enforced", capped.BudgetStop)
	}
	if capped.Spend.Attempts >= unbounded.Spend.Attempts {
		t.Errorf("--max-duration 1ns fired %d probes against the control's %d — the budget changed nothing",
			capped.Spend.Attempts, unbounded.Spend.Attempts)
	}
	if len(capped.Traces) != len(unbounded.Traces) {
		t.Errorf("a stopped run reported %d traces, want %d — a hypothesis that was never attempted must still be reported, as INCONCLUSIVE",
			len(capped.Traces), len(unbounded.Traces))
	}

	// --output is a flag too: honouring it means nothing was written to the
	// default path in the working directory.
	if _, err := os.Stat("attack.trace.json"); err == nil {
		t.Error("--output was given, yet traces were also written to the default attack.trace.json")
	}
}

// TestAttackRunPlantDirDecidesWhetherACanaryIsPlanted pins the flag that decides
// whether nox writes into the system under test. Both directions matter: without
// it nothing is ever written (nox never guesses a directory), and with it the
// canary the exfiltration scenario needs actually exists — a scenario whose bait
// was never planted can only ever come back INCONCLUSIVE, which reads far too
// much like "the target resisted it".
func TestAttackRunPlantDirDecidesWhetherACanaryIsPlanted(t *testing.T) {
	exfilPlan := &attack.Plan{Hypotheses: []attack.Hypothesis{{ID: "h-exfil", ScenarioID: attack.ScenarioExfilFSNet}}}
	injectionPlan := &attack.Plan{Hypotheses: []attack.Hypothesis{{ID: "h-pi", ScenarioID: attack.ScenarioPIDirect}}}

	t.Run("no flag plants nothing", func(t *testing.T) {
		var planted []attack.PlantedCanary
		var cleanup attack.CleanupFunc
		var err error
		_, _ = captureCLI(t, func() int {
			planted, cleanup, err = plantCanaries(exfilPlan, "nox", "", attack.ProfileSandbox, true)
			return 0
		})
		if err != nil {
			t.Fatalf("omitting --plant-dir must not be an error: %v", err)
		}
		if len(planted) != 0 {
			t.Errorf("planted %d canaries without --plant-dir; nox must never guess where to write", len(planted))
		}
		if cleanup == nil {
			t.Error("cleanup must always be returned, so the caller's defer is never nil")
		}
	})

	t.Run("flag plants the canary the scenario needs", func(t *testing.T) {
		dir := t.TempDir()
		var planted []attack.PlantedCanary
		var cleanup attack.CleanupFunc
		var err error
		_, _ = captureCLI(t, func() int {
			planted, cleanup, err = plantCanaries(exfilPlan, "nox", dir, attack.ProfileSandbox, true)
			return 0
		})
		if err != nil {
			t.Fatalf("planting into an existing directory: %v", err)
		}
		if len(planted) != 1 {
			t.Fatalf("--plant-dir planted %d canaries, want 1", len(planted))
		}
		path := filepath.Join(dir, attack.ExfilFileName())
		if _, statErr := os.Stat(path); statErr != nil {
			t.Fatalf("--plant-dir did not create %s: %v", path, statErr)
		}
		if err := cleanup(); err != nil {
			t.Fatalf("cleanup: %v", err)
		}
		if _, statErr := os.Stat(path); !os.IsNotExist(statErr) {
			t.Errorf("the canary survived cleanup at %s — a fake secret left in someone's filesystem", path)
		}
	})

	t.Run("flag is inert when no scenario uses a canary", func(t *testing.T) {
		dir := t.TempDir()
		var planted []attack.PlantedCanary
		var err error
		_, out := captureCLI(t, func() int {
			planted, _, err = plantCanaries(injectionPlan, "nox", dir, attack.ProfileSandbox, true)
			return 0
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(planted) != 0 {
			t.Errorf("planted %d canaries for a plan that needs none", len(planted))
		}
		entries, readErr := os.ReadDir(dir)
		if readErr != nil {
			t.Fatal(readErr)
		}
		if len(entries) != 0 {
			t.Errorf("wrote %d files into --plant-dir for a plan that needs no canary", len(entries))
		}
		// Silently doing nothing is how an operator concludes the scenario ran.
		if !strings.Contains(out, "nothing planted") {
			t.Errorf("an inert --plant-dir must say so; got: %s", out)
		}
	})
}

// flagSpec is one documented flag, the argument that exercises it, and the
// reason it is not a no-op. effect is mandatory: an entry with nothing to say
// about what the flag changes is the state this file exists to make visible.
type flagSpec struct {
	name   string
	arg    string // the --name=value form used to prove the flag is registered
	effect string
}

// subcommandFlags is the flag inventory for `nox attack`. Its two halves are
// cross-checked against each other: the usage text a user reads and the flags
// the FlagSet actually accepts. A flag documented but never registered is a lie
// in --help; a flag registered but undocumented is a capability nobody can find;
// a flag with no effect note is the --max-duration bug waiting to happen again.
var subcommandFlags = []struct {
	name  string
	usage string
	run   func([]string) int
	base  []string // arguments that keep the command offline and short-circuited
	flags []flagSpec
}{
	{
		name:  "plan",
		usage: attackPlanUsage,
		run:   runAttackPlan,
		base:  []string{"--findings=testdata/nox-flag-efficacy-absent.json"},
		flags: []flagSpec{
			{"findings", "--findings=testdata/nox-flag-efficacy-absent.json", "names the scan artifact the plan is grounded in; a missing file is a hard error"},
			{"inventory", "--inventory=testdata/nox-flag-efficacy-absent.json", "supplies the tool matrix that grounds tool and exfiltration hypotheses"},
			{"evidence", "--evidence=testdata/nox-flag-efficacy-absent.json", "carries what the scan established onto each hypothesis; a missing file warns and plans without it"},
			{"output", "--output=testdata/nox-flag-efficacy-absent.json", "chooses where the plan is written"},
			{"json", "--json=true", "prints the plan instead of a summary"},
		},
	},
	{
		name:  "run",
		usage: attackRunUsage,
		run:   runAttackRun,
		base:  []string{"--plan=testdata/nox-flag-efficacy-absent.json", "--profile=safe"},
		flags: []flagSpec{
			{"plan", "--plan=testdata/nox-flag-efficacy-absent.json", "selects the plan to execute (TestAttackRunMaxDurationStopsTheRun reads a plan from an explicit path)"},
			{"target", "--target=http://127.0.0.1:1", "the base URL every probe is sent to"},
			{"route", "--route=/chat", "the path probes are posted to; wrong route means every probe 404s and nothing can be confirmed"},
			{"fields", "--fields=persona,message", "the request fields injected into (TestSplitCSV)"},
			{"reply-field", "--reply-field=answer", "the JSON key the model reply is read from; the oracles see nothing without it"},
			{"profile", "--profile=safe", "selects the target adapter (TestTargetForSafeProfileCannotReachTheNetwork)"},
			{"samples", "--samples=1", "size of the determinism gate (TestAttackRunMaxDurationStopsTheRun runs with --samples 1)"},
			{"min-hits", "--min-hits=1", "k-of-n reproduction threshold before a CONFIRM; enforced in core/attack RunConfig.withDefaults"},
			{"max-attempts", "--max-attempts=5", "attempt budget (TestBudgetFromOverlaysDefaults)"},
			{"max-requests", "--max-requests=5", "network-request budget (TestBudgetFromOverlaysDefaults)"},
			{"max-duration", "--max-duration=1ns", "wall-clock budget (TestAttackRunMaxDurationStopsTheRun)"},
			{"timeout", "--timeout=1s", "per-request HTTP timeout carried into the HTTP target"},
			{"seed", "--seed=other", "derives the canaries; the same seed replays identically (core/attack TestMintCanariesDeterministic)"},
			{"plant-dir", "--plant-dir=testdata", "plants the exfiltration canary (TestAttackRunPlantDirDecidesWhetherACanaryIsPlanted)"},
			{"output", "--output=testdata/nox-flag-efficacy-absent.json", "chooses where traces are written (TestAttackRunMaxDurationStopsTheRun)"},
			{"authorize", "--authorize=true", "lifts the refusal on an ACTIVE profile (TestActiveSubcommandsRefuseWithoutAuthorization)"},
		},
	},
	{
		name:  "replay",
		usage: attackReplayUsage,
		run:   runAttackReplay,
		base:  []string{"TRACE-1", "--trace=testdata/nox-flag-efficacy-absent.json"},
		flags: []flagSpec{
			{"trace", "--trace=testdata/nox-flag-efficacy-absent.json", "selects the recorded run to replay"},
			{"target", "--target=http://127.0.0.1:1", "the target the recorded payload is re-sent to; required"},
			{"route", "--route=/chat", "overrides the recorded route"},
			{"fields", "--fields=persona,message", "overrides the recorded fields (TestSplitCSV)"},
			{"reply-field", "--reply-field=answer", "the JSON key the model reply is read from"},
			{"profile", "--profile=sandbox", "selects the target adapter (TestTargetForSafeProfileCannotReachTheNetwork)"},
			{"samples", "--samples=1", "size of the determinism gate"},
			{"min-hits", "--min-hits=1", "k-of-n reproduction threshold before a CONFIRM"},
			{"timeout", "--timeout=1s", "per-request HTTP timeout"},
			{"seed", "--seed=other", "must match the original run or the canaries differ and nothing reproduces"},
			{"authorize", "--authorize=true", "lifts the refusal (TestActiveSubcommandsRefuseWithoutAuthorization)"},
		},
	},
	{
		name:  "regress",
		usage: attackRegressUsage,
		run:   runAttackRegress,
		base:  []string{"--trace=testdata/nox-flag-efficacy-absent.json", "--suite=testdata/nox-flag-efficacy-absent.json"},
		flags: []flagSpec{
			{"record", "--record=true", "switches the command from running the suite to deriving it"},
			{"trace", "--trace=testdata/nox-flag-efficacy-absent.json", "the traces a suite is derived from"},
			{"suite", "--suite=testdata/nox-flag-efficacy-absent.json", "the case suite that is run"},
			{"target", "--target=http://127.0.0.1:1", "the target the cases are re-sent to; required unless --record"},
			{"route", "--route=/chat", "overrides each case's recorded route (core/attack TestRoutePrecedence)"},
			{"fields", "--fields=persona,message", "overrides the recorded fields (TestSplitCSV)"},
			{"reply-field", "--reply-field=answer", "the JSON key the model reply is read from"},
			{"profile", "--profile=sandbox", "selects the target adapter (TestTargetForSafeProfileCannotReachTheNetwork)"},
			{"timeout", "--timeout=1s", "per-request HTTP timeout"},
			{"seed", "--seed=other", "must match the original run"},
			{"output", "--output=testdata/nox-flag-efficacy-absent.json", "chooses where the suite result is written"},
			{"authorize", "--authorize=true", "lifts the refusal (TestActiveSubcommandsRefuseWithoutAuthorization)"},
		},
	},
	{
		name:  "mcp",
		usage: attackMCPUsage,
		run:   runAttackMCP,
		base:  nil, // no transport: the command short-circuits before it connects
		flags: []flagSpec{
			{"command", "--command=nox-attack-mcp-should-never-run", "selects the stdio transport (TestAttackMCPRefusesWithoutAuthorize)"},
			{"url", "--url=http://127.0.0.1:1", "selects the http transport (TestAttackMCPRefusesWithoutAuthorize)"},
			{"addr", "--addr=127.0.0.1:1", "selects the grpc transport (TestAttackMCPRefusesWithoutAuthorize)"},
			{"dir", "--dir=testdata", "working directory of the stdio subprocess"},
			{"profile", "--profile=sandbox", "decides whether --authorize is required"},
			{"samples", "--samples=1", "manifest captures for the determinism gate"},
			{"timeout", "--timeout=1s", "per-request MCP timeout"},
			{"output", "--output=testdata/nox-flag-efficacy-absent.json", "chooses where the traces are written"},
			{"authorize", "--authorize=true", "lifts the refusal (TestAttackMCPRefusesWithoutAuthorize)"},
		},
	},
}

var usageFlagPattern = regexp.MustCompile(`--([a-z][a-z0-9-]*)`)

// TestAttackFlagInventoryMatchesTheHelpText is the parity half: the usage text
// and the inventory above must name the same flags. Adding a flag to a command
// without adding it here fails, which is the point — the entry cannot be written
// without stating what the flag changes.
func TestAttackFlagInventoryMatchesTheHelpText(t *testing.T) {
	for _, cmd := range subcommandFlags {
		t.Run(cmd.name, func(t *testing.T) {
			documented := map[string]bool{}
			for _, m := range usageFlagPattern.FindAllStringSubmatch(cmd.usage, -1) {
				documented[m[1]] = true
			}
			if len(documented) == 0 {
				t.Fatalf("no flags found in the usage text for %q; the parity check is not exercising anything", cmd.name)
			}

			inventory := map[string]bool{}
			for _, f := range cmd.flags {
				if f.effect == "" {
					t.Errorf("--%s has no recorded effect: say what it changes, or record it as informational", f.name)
				}
				if !strings.HasPrefix(f.arg, "--"+f.name+"=") {
					t.Errorf("--%s is exercised with %q, which does not set that flag", f.name, f.arg)
				}
				inventory[f.name] = true
			}

			var undocumented, unguarded []string
			for name := range inventory {
				if !documented[name] {
					undocumented = append(undocumented, name)
				}
			}
			for name := range documented {
				if !inventory[name] {
					unguarded = append(unguarded, name)
				}
			}
			sort.Strings(undocumented)
			sort.Strings(unguarded)
			if len(undocumented) > 0 {
				t.Errorf("inventoried but absent from `nox attack %s --help`: %v", cmd.name, undocumented)
			}
			if len(unguarded) > 0 {
				t.Errorf("documented in `nox attack %s --help` but missing from the flag inventory: %v — add an entry naming what each one changes", cmd.name, unguarded)
			}
		})
	}
}

const undefinedFlag = "flag provided but not defined"

// TestAttackDocumentedFlagsAreRegistered is the other half: every flag the help
// text promises must actually be accepted by the FlagSet. Help text drifts more
// quietly than code — a renamed flag leaves a documented name that dies in the
// parser, and the operator reads the failure as their own typo.
//
// Every invocation here is short-circuited before it reaches a network: the
// paths are absent, the profiles that need --authorize do not get it, and the
// mcp cases either name no transport or stop at the authorization refusal.
func TestAttackDocumentedFlagsAreRegistered(t *testing.T) {
	for _, cmd := range subcommandFlags {
		t.Run(cmd.name, func(t *testing.T) {
			for _, f := range cmd.flags {
				// The tested flag goes last so it wins over any base value.
				args := append(append([]string{}, cmd.base...), f.arg)
				_, out := captureCLI(t, func() int { return cmd.run(args) })
				if strings.Contains(out, undefinedFlag) {
					t.Errorf("`nox attack %s --help` documents --%s, but the command rejects it: %s", cmd.name, f.name, strings.TrimSpace(out))
				}
			}

			// Negative control: the check above can only mean something if an
			// unknown flag really does produce that message.
			args := append(append([]string{}, cmd.base...), "--nox-flag-efficacy-not-a-flag=1")
			_, out := captureCLI(t, func() int { return cmd.run(args) })
			if !strings.Contains(out, undefinedFlag) {
				t.Errorf("an unknown flag was not rejected by `nox attack %s`; the registration check cannot fail: %s", cmd.name, strings.TrimSpace(out))
			}
		})
	}
}

// TestAttackRunHelpStatesTheRealBudgetDefaults pins the help text against the
// budget the engine actually applies. An operator reads --help to decide whether
// they need to pass a limit at all; a default they were told is 200 and is
// really 500 is a 2.5x understatement of how much traffic an ACTIVE run may
// send at a system they own.
func TestAttackRunHelpStatesTheRealBudgetDefaults(t *testing.T) {
	cases := []struct {
		flag string
		want string
	}{
		{"--max-attempts", "200"},
		{"--max-requests", "500"},
		{"--max-duration", "5m"},
	}
	for _, c := range cases {
		line := ""
		for _, l := range strings.Split(attackRunUsage, "\n") {
			if strings.Contains(l, c.flag+" ") {
				line = l
				break
			}
		}
		if line == "" {
			t.Errorf("%s is not documented in the run usage", c.flag)
			continue
		}
		if !strings.Contains(line, "default "+c.want) {
			t.Errorf("help says %q, but the engine's default is %s", strings.TrimSpace(line), c.want)
		}
	}
}

// TestReplayAndRegressEnforceTheirWallClockBudget records a live gap rather than
// a passing guard. `nox attack run` fixed --max-duration by injecting a real
// clock at the CLI edge (RunConfig.Clock); runAttackReplay and runAttackRegress
// build their RunConfig with attack.DefaultBudget() and no Clock, so
// Budget.Duration — a declared five-minute ceiling on two ACTIVE commands that
// re-send attack payloads — can never trip. Neither command exposes a
// --max-duration flag, so nothing in --help is false; the ceiling is simply
// inert, which is the same failure one layer down.
// Replay and regress carry no wall-clock budget, and that is correct — but it
// has to stay correct for a stated reason rather than by accident.
//
// `attack run` enumerates hypotheses x payloads x fields x samples, so it needs
// a duration ceiling and it registers --max-duration to expose one. Replay
// re-fires ONE recorded probe --samples times; a suite fires each case's probe
// its recorded sample count. Both are inherently bounded, and neither advertises
// a duration flag.
//
// So the invariant is: a command must not carry a budget nothing enforces. An
// inert control implying a ceiling that does not exist is the same defect class
// as a flag that parses and does nothing. If replay or regress ever grows
// --max-duration, it must also grow a Clock, and this test should become the
// enforcement assertion instead.
func TestReplayAndRegressDoNotAdvertiseABudgetTheyDoNotEnforce(t *testing.T) {
	src := readCLISource(t, "attack_cmd.go")

	replay := funcBody(t, src, "runAttackReplay")
	regress := funcBody(t, src, "runAttackRegress")

	for name, body := range map[string]string{"runAttackReplay": replay, "runAttackRegress": regress} {
		if strings.Contains(body, "max-duration") {
			t.Errorf("%s registers --max-duration but neither Replay nor RunSuite consults a "+
				"Budget — wire a Clock and enforce it, or drop the flag", name)
		}
		if strings.Contains(body, "Clock:") {
			t.Errorf("%s sets a Clock, but nothing in Replay/RunSuite reads the Budget it would "+
				"drive — an inert control", name)
		}
	}

	// The command that DOES enforce a duration must still inject a clock, or
	// --max-duration silently does nothing (the bug this guards).
	run := funcBody(t, src, "runAttackRun")
	if !strings.Contains(run, "Clock:") {
		t.Error("runAttackRun registers --max-duration but injects no Clock; the budget is inert")
	}
}

// readCLISource reads one file from this package for source-level assertions.
func readCLISource(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(name) //nolint:gosec // package-local test input
	if err != nil {
		t.Fatalf("reading %s: %v", name, err)
	}
	return string(data)
}

// funcBody returns the CODE of the named top-level func, with line comments
// stripped.
//
// Stripping matters: this guard asserts on what a function DOES, and a comment
// explaining why a field is absent mentions the very identifiers being searched
// for. Matching prose would make the guard fire on its own documentation.
func funcBody(t *testing.T, src, name string) string {
	t.Helper()
	start := strings.Index(src, "func "+name+"(")
	if start < 0 {
		t.Fatalf("func %s not found", name)
	}
	body := src[start:]
	if end := strings.Index(body, "\n}\n"); end >= 0 {
		body = body[:end]
	}
	var code strings.Builder
	for _, line := range strings.Split(body, "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	return code.String()
}
