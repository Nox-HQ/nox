package main

import (
	"bytes"
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/intel"
)

// Blast radius is a paid intelligence capability: the service assesses what a
// candidate reaches in an organisation's estate, from the estate the
// organisation describes. These two commands build that description from what
// nox knows locally. Both print what they would send and send nothing unless
// --upload is given, because an inventory describes the organisation's own
// infrastructure and should be read before it leaves.
//
// Uploading needs an organisation token in NOX_INTEL_TOKEN on a plan that
// includes blast_radius. A `nox intel login` session is an operator session and
// is deliberately never accepted as a customer credential by the service.

func runIntelComponents(args []string) int {
	fs := flag.NewFlagSet("intel components", flag.ContinueOnError)
	service := fs.String("service", "", "service name (default: the target directory's name)")
	exposed := fs.Bool("exposed", false, "declare that the service accepts untrusted input (e.g. is internet-facing)")
	capsCSV := fs.String("capabilities", "", "comma-separated capabilities to add, e.g. secret.read,identity.assume")
	idsCSV := fs.String("identities", "", "comma-separated roles or principals the service can act as")
	dataCSV := fs.String("data-classes", "", "comma-separated classes of data the service can reach")
	upload := fs.Bool("upload", false, "send the inventory to the intelligence service (needs NOX_INTEL_TOKEN)")
	endpoint := fs.String("endpoint", intelEndpointDefault(), "intelligence service base URL")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nox intel components [path] [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Describe one service's dependencies for blast-radius assessment. Prints the\n")
		fmt.Fprintf(os.Stderr, "inventory; --upload replaces this service's components on the service and\n")
		fmt.Fprintf(os.Stderr, "leaves every other service's alone.\n\n")
		fs.PrintDefaults()
	}
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	target := "."
	if fs.NArg() > 0 {
		target = fs.Arg(0)
	}
	name := *service
	if name == "" {
		abs, err := filepath.Abs(target)
		if err != nil {
			fmt.Fprintf(os.Stderr, "nox intel components: %v\n", err)
			return 2
		}
		name = intel.ServiceNameFrom(filepath.Base(abs))
	}
	opts := intel.InventoryOptions{
		Service:      name,
		Exposed:      *exposed,
		Capabilities: splitCSV(*capsCSV),
		Identities:   splitCSV(*idsCSV),
		DataClasses:  splitCSV(*dataCSV),
	}

	inv, err := core.DeriveServiceInventory(context.Background(), target, opts, core.ScanOptions{ToolVersion: version})
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel components: %v\n", err)
		return 2
	}

	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(inv); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel components: %v\n", err)
		return 1
	}
	imported := 0
	for _, c := range inv.Components {
		if c.VulnerablePathReachable {
			imported++
		}
	}
	fmt.Fprintf(os.Stderr, "\n%s: %d component(s), %d imported by the service's own code, %d capability(ies) derived.\n",
		inv.Service, len(inv.Components), imported, len(inv.Derived))
	if !*upload {
		fmt.Fprintf(os.Stderr, "Nothing was sent. Re-run with --upload to replace this service's components.\n")
		return 0
	}

	token, ok := orgToken("nox intel components")
	if !ok {
		return 2
	}
	path := "/v1/org/services/" + url.PathEscape(inv.Service) + "/components"
	var out struct {
		Components int `json:"components"`
	}
	if code := sendJSON(http.MethodPut, strings.TrimRight(*endpoint, "/")+path, token,
		map[string]any{"components": inv.Components}, &out, "nox intel components"); code != 0 {
		return code
	}
	fmt.Fprintf(os.Stderr, "Uploaded %d component(s) for %s.\n", out.Components, inv.Service)
	return 0
}

func runIntelEvidence(args []string) int {
	fs := flag.NewFlagSet("intel evidence", flag.ContinueOnError)
	candidate := fs.String("candidate", "", "fingerprint of the candidate the run exercised (64 hex characters)")
	component := fs.String("component", "", "id of the component the run was aimed at (see nox intel components)")
	tracesCSV := fs.String("traces", "", "comma-separated trace ids to send (default: every trace that observed a violation)")
	upload := fs.Bool("upload", false, "send the evidence to the intelligence service (needs NOX_INTEL_TOKEN)")
	endpoint := fs.String("endpoint", intelEndpointDefault(), "intelligence service base URL")
	fs.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: nox intel evidence <attack-result.json> --candidate <fingerprint> [flags]\n\n")
		fmt.Fprintf(os.Stderr, "Turn `nox attack run` traces into exploit evidence for one intelligence\n")
		fmt.Fprintf(os.Stderr, "candidate. nox cannot tell which candidate a trace is about: an attack is\n")
		fmt.Fprintf(os.Stderr, "grounded in your own findings, not in intelligence. --candidate is your\n")
		fmt.Fprintf(os.Stderr, "statement that the run exercised it, and is sent as that.\n\n")
		fs.PrintDefaults()
	}
	if err := parseFlagsAnywhere(fs, args); err != nil {
		return 2
	}
	if fs.NArg() != 1 {
		fs.Usage()
		return 2
	}
	if !intel.ValidCandidateFingerprint(*candidate) {
		fmt.Fprintf(os.Stderr, "nox intel evidence: --candidate must be a full candidate fingerprint (64 lowercase hex characters)\n")
		return 2
	}
	if *component != "" && !intel.ValidComponentID(*component) {
		fmt.Fprintf(os.Stderr, "nox intel evidence: --component %q is not a valid component id\n", *component)
		return 2
	}

	raw, err := os.ReadFile(fs.Arg(0)) // #nosec G304 -- the operator names the file
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel evidence: %v\n", err)
		return 2
	}
	var result attack.Result
	if err := json.Unmarshal(raw, &result); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel evidence: %s is not an attack result: %v\n", fs.Arg(0), err)
		return 2
	}

	evs, notes, err := evidenceFromResult(&result, *candidate, *component, splitCSV(*tracesCSV))
	if err != nil {
		fmt.Fprintf(os.Stderr, "nox intel evidence: %v\n", err)
		return 2
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(evs); err != nil {
		fmt.Fprintf(os.Stderr, "nox intel evidence: %v\n", err)
		return 1
	}
	for _, n := range notes {
		fmt.Fprintf(os.Stderr, "%s\n", n)
	}
	if len(evs) == 0 {
		fmt.Fprintf(os.Stderr, "\nNo trace in %s observed a violation; nothing to send. Name traces with --traces to send prevented or inconclusive runs.\n", fs.Arg(0))
		return 0
	}
	if !*upload {
		fmt.Fprintf(os.Stderr, "\n%d run(s) bound to candidate %s. Nothing was sent. Re-run with --upload to send.\n", len(evs), (*candidate)[:12])
		return 0
	}

	token, ok := orgToken("nox intel evidence")
	if !ok {
		return 2
	}
	base := strings.TrimRight(*endpoint, "/")
	for _, ev := range evs {
		if code := sendJSON(http.MethodPost, base+"/v1/org/exploit-evidence", token, ev, nil, "nox intel evidence"); code != 0 {
			return code
		}
	}
	fmt.Fprintf(os.Stderr, "Sent %d run(s) for candidate %s.\n", len(evs), (*candidate)[:12])
	return 0
}

// evidenceFromResult binds an attack result's traces to one candidate.
//
// By default only traces that observed a violation are sent: a prevented or
// inconclusive run raises no reach, so it would only add records. Named traces
// are sent whatever their state, because naming one is asking for it.
//
// Deterministic is read from the winning oracle — anything but a semantic
// judgment is machine-checkable — and Reproduced from the determinism gate, so
// the service's CONFIRMED rung can only be reached by a run that earned it here.
func evidenceFromResult(r *attack.Result, candidate, component string, only []string) ([]intel.ExploitEvidence, []string, error) {
	if _, err := time.Parse(time.RFC3339, r.GeneratedAt); err != nil {
		return nil, nil, fmt.Errorf("the attack result has no RFC3339 generated_at; the service will not substitute its own clock")
	}
	want := map[string]bool{}
	for _, id := range only {
		want[id] = true
	}
	var out []intel.ExploitEvidence
	var notes []string
	found := map[string]bool{}
	for i := range r.Traces {
		tr := &r.Traces[i]
		if len(want) > 0 && !want[tr.ID] {
			continue
		}
		found[tr.ID] = true
		if len(want) == 0 && tr.Evidence == nil {
			continue
		}
		if !intel.ValidComponentID(tr.ID) {
			return nil, nil, fmt.Errorf("trace id %q cannot be sent as a trace id", tr.ID)
		}
		ev := intel.ExploitEvidence{
			TraceID:        tr.ID,
			Fingerprint:    candidate,
			ComponentID:    component,
			Exploitability: string(tr.Exploitability),
			ObservedAt:     r.GeneratedAt,
		}
		if tr.Evidence != nil {
			ev.Deterministic = tr.Evidence.OracleKind != attack.OracleSemantic
			ev.Reproduced = tr.Evidence.Reproduced
		} else {
			ev.Deterministic = tr.Ledger.HasDeterministic()
		}
		out = append(out, ev)
		notes = append(notes, fmt.Sprintf("  %s: %s — %s", tr.ID, tr.Exploitability, tr.Objective))
	}
	for id := range want {
		if !found[id] {
			return nil, nil, fmt.Errorf("no trace %q in the attack result", id)
		}
	}
	return out, notes, nil
}

// orgToken returns the organisation token uploads authenticate with.
func orgToken(cmd string) (string, bool) {
	token := strings.TrimSpace(os.Getenv("NOX_INTEL_TOKEN"))
	if token == "" {
		fmt.Fprintf(os.Stderr, "%s: --upload needs an organisation token in NOX_INTEL_TOKEN.\n", cmd)
		fmt.Fprintf(os.Stderr, "A `nox intel login` session will not do: it signs in an operator, and the\n")
		fmt.Fprintf(os.Stderr, "service never accepts an operator session as a customer credential.\n")
		return "", false
	}
	return token, true
}

// sendJSON sends body and decodes the reply into out (which may be nil),
// explaining the refusals a customer will actually meet.
func sendJSON(method, endpoint, token string, body, out any, cmd string) int {
	buf, err := json.Marshal(body)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		return 1
	}
	req, err := http.NewRequest(method, endpoint, bytes.NewReader(buf))
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		return 1
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s: %v\n", cmd, err)
		return 1
	}
	defer func() { _ = resp.Body.Close() }()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 300 {
		if out != nil {
			_ = json.Unmarshal(raw, out)
		}
		return 0
	}
	var e struct {
		Error string `json:"error"`
	}
	msg := strings.TrimSpace(string(raw))
	if json.Unmarshal(raw, &e) == nil && e.Error != "" {
		msg = e.Error
	}
	switch resp.StatusCode {
	case http.StatusUnauthorized:
		msg += " — NOX_INTEL_TOKEN was not accepted as an organisation token"
	case http.StatusForbidden:
		msg += " — blast radius needs a plan that includes it (Security or above)"
	}
	fmt.Fprintf(os.Stderr, "%s: %s (HTTP %d)\n", cmd, msg, resp.StatusCode)
	return 1
}
