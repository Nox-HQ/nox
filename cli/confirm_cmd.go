package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/nox-hq/nox/core/confirm"
	"github.com/nox-hq/nox/core/report"
)

// confirmUsage documents the ACTIVE, opt-in nature of the command up front.
const confirmUsage = `Usage: nox confirm --target <url> [flags]

  Dynamically confirm static AI prompt-injection findings by firing an
  adversarial corpus at a RUNNING target and checking whether the model is
  actually goal-hijacked. Turns a static pattern match (AGENTFLOW-001,
  TAINT-AI-001, AI-PI-*) into a demonstrated exploit — CONFIRMED (with evidence)
  or UNCONFIRMED (a cleared false positive).

  THIS IS AN ACTIVE CAPABILITY. It sends attack payloads over the network to
  --target. It is NOT part of ` + "`nox scan`" + ` and never runs automatically. nox does
  NOT run or sandbox the target: YOU point it at a target you own and have
  isolated, and you must pass --authorize to acknowledge that.

Flags:
  --target <url>     base URL of the running target app (required)
  --findings <path>  findings.json from a prior ` + "`nox scan`" + ` (default findings.json)
  --route <path>     HTTP route to probe, e.g. /chat (required unless --app-src)
  --fields <list>    comma-separated request fields to inject, e.g. persona,message
  --app-src <path>   Flask app source to recover --route/--fields from (optional)
  --output <path>    write confirmations.json here (default confirmations.json)
  --reply-field <k>  JSON key in the app response holding the model reply (default reply)
  --samples <n>      determinism samples per candidate exploit (default 2)
  --min-hits <k>     min signal hits of n to CONFIRM; k<n = k-of-n for real models (default n)
  --timeout <dur>    per-request HTTP timeout (default 15s)
  --authorize        REQUIRED: acknowledge you are authorized to fire attacks at --target

Exit: 0 = nothing confirmed, 1 = at least one CONFIRMED exploit, 2 = error.
`

func runConfirm(args []string) int {
	fs := flag.NewFlagSet("confirm", flag.ContinueOnError)
	var (
		target     string
		findingsIn string
		route      string
		fieldsCSV  string
		appSrc     string
		output     string
		replyField string
		samples    int
		minHits    int
		timeout    time.Duration
		authorize  bool
	)
	fs.StringVar(&target, "target", "", "base URL of the running target app (required)")
	fs.StringVar(&findingsIn, "findings", "findings.json", "path to findings.json from a prior nox scan")
	fs.StringVar(&route, "route", "", "HTTP route to probe (e.g. /chat)")
	fs.StringVar(&fieldsCSV, "fields", "", "comma-separated request fields to inject (e.g. persona,message)")
	fs.StringVar(&appSrc, "app-src", "", "Flask app source to recover route/fields from")
	fs.StringVar(&output, "output", "confirmations.json", "output file path")
	fs.StringVar(&replyField, "reply-field", "reply", "JSON key in the app response holding the model reply")
	fs.IntVar(&samples, "samples", 2, "determinism samples per candidate exploit")
	fs.IntVar(&minHits, "min-hits", 0, "min signal hits of samples to CONFIRM (default = samples)")
	fs.DurationVar(&timeout, "timeout", 15*time.Second, "per-request HTTP timeout")
	fs.BoolVar(&authorize, "authorize", false, "acknowledge you are authorized to fire attacks at --target")
	fs.Usage = func() { fmt.Fprint(os.Stderr, confirmUsage) }

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if target == "" {
		fmt.Fprintln(os.Stderr, "error: --target is required")
		fs.Usage()
		return 2
	}
	if !authorize {
		fmt.Fprintln(os.Stderr, "error: nox confirm is ACTIVE — it fires attack payloads at --target.")
		fmt.Fprintln(os.Stderr, "Pass --authorize to confirm you own and have isolated the target. Refusing to run.")
		return 2
	}
	if route == "" && appSrc == "" {
		fmt.Fprintln(os.Stderr, "error: supply --route (and --fields), or --app-src to recover them")
		return 2
	}

	// Reflection-immunity invariant, asserted before firing a single payload. If
	// this fails, a bare echo could masquerade as a hijack — fail closed.
	if err := confirm.AssertReflectionImmune(); err != nil {
		fmt.Fprintf(os.Stderr, "error: corpus failed reflection-immunity check: %v\n", err)
		return 2
	}

	// Read findings.json produced by a prior `nox scan`.
	findingsList, err := report.LoadFindingsFile(findingsIn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: reading %s: %v\n", findingsIn, err)
		return 2
	}

	var fields []string
	for _, f := range strings.Split(fieldsCSV, ",") {
		if s := strings.TrimSpace(f); s != "" {
			fields = append(fields, s)
		}
	}

	cfg := confirm.Config{
		Target:     target,
		Route:      route,
		Fields:     fields,
		AppSrc:     appSrc,
		N:          samples,
		K:          minHits,
		Label:      target,
		ReplyField: replyField,
	}

	d := &confirm.Driver{
		Poster: confirm.HTTPPoster{Client: &http.Client{Timeout: timeout}},
		Now:    time.Now,
	}

	fmt.Printf("nox confirm — ACTIVE dynamic confirmation against %s\n", target)
	fmt.Println("  (nox is not sandboxing this target; you are responsible for isolating it)")

	ctx := context.Background()
	rep, err := d.Run(ctx, findingsList, cfg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: confirmation run failed: %v\n", err)
		return 2
	}

	out, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling report: %v\n", err)
		return 2
	}
	if err := os.WriteFile(output, append(out, '\n'), 0o644); err != nil { //nolint:gosec // report artifact, not a secret
		fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", output, err)
		return 2
	}

	printConfirmSummary(rep, output)

	if rep.AnyConfirmed() {
		return 1
	}
	return 0
}

func printConfirmSummary(rep *confirm.Report, output string) {
	if len(rep.AIFindingsConsidered) == 0 {
		fmt.Println("[confirm] no AI prompt-injection findings in findings.json — nothing to confirm")
		fmt.Printf("[confirm] wrote %s\n", output)
		return
	}
	fmt.Printf("[confirm] AI findings considered: %s → %d unique sink(s)\n",
		strings.Join(rep.AIFindingsConsidered, ", "), rep.UniqueSinks)
	for i := range rep.Results {
		r := rep.Results[i]
		fmt.Printf("\n  finding %s @ %s:%d  route=%s fields=%s\n",
			r.RuleID, r.Location.FilePath, r.Location.StartLine, r.Route, strings.Join(r.RequestFields, ","))
		fmt.Printf("    static_flag = nox-flagged   |   DYNAMIC VERDICT: %s\n", r.Verdict)
		if r.ControlOK != nil {
			fmt.Printf("    benign-control-safe = %v\n", *r.ControlOK)
		}
		if r.Evidence != nil {
			ev := r.Evidence
			fmt.Printf("    winning field   : %s\n", ev.Field)
			fmt.Printf("    winning payload : [%s/%s] %s\n", ev.Category, ev.PayloadID, truncate(ev.Payload, 80))
			fmt.Printf("    hijack signal   : %s\n", ev.Signal)
			fmt.Printf("    model response  : %s\n", truncate(ev.ModelResponse, 160))
			fmt.Printf("    determinism     : %d/%d hits (k=%d) reproduced=%v byte_identical=%v\n",
				ev.Determinism.SignalHits, ev.Determinism.N, ev.Determinism.K,
				ev.Determinism.Reproduced, ev.Determinism.ByteIdentical)
		} else if r.Note != "" {
			fmt.Printf("    note: %s\n", r.Note)
		}
	}
	verdict := "UNCONFIRMED"
	if rep.AnyConfirmed() {
		verdict = "CONFIRMED"
	}
	fmt.Printf("\n  => %s: %s\n", rep.Label, verdict)
	fmt.Printf("[confirm] wrote %s\n", output)
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
