package assess

import (
	"bytes"
	"flag"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	osvsource "github.com/nox-hq/nox-core/vulnsource/osv"
	nox "github.com/nox-hq/nox/core"
	"github.com/nox-hq/nox/core/attack"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/plugincap"
)

var update = flag.Bool("update", false, "rewrite the golden files from the current output")

func dep(pkg, version, fixed string, sev findings.Severity, fp string) findings.Finding {
	return findings.Finding{
		RuleID:      "VULN-001",
		Severity:    sev,
		Confidence:  findings.ConfidenceHigh,
		Location:    findings.Location{FilePath: "package-lock.json", StartLine: 1},
		Message:     "Known vulnerability in " + pkg + "@" + version,
		Fingerprint: fp,
		Metadata: map[string]string{
			"ecosystem": "npm", "package": pkg, "version": version, "fixed_in": fixed,
			"applicability": "undetermined",
		},
		Exploitability: "POTENTIAL",
	}
}

func typosquat(pkg, version, fp string) findings.Finding {
	return findings.Finding{
		RuleID:         "VULN-002",
		Severity:       findings.SeverityMedium,
		Confidence:     findings.ConfidenceLow,
		Location:       findings.Location{FilePath: "package-lock.json", StartLine: 1},
		Message:        "Possible typosquatting: " + pkg + " is suspiciously similar to a popular package",
		Fingerprint:    fp,
		Metadata:       map[string]string{"ecosystem": "npm", "package": pkg, "version": version},
		Exploitability: "POTENTIAL",
	}
}

func promptInjection() findings.Finding {
	return findings.Finding{
		RuleID:      "TAINT-AI-001",
		Severity:    findings.SeverityHigh,
		Confidence:  findings.ConfidenceMedium,
		Location:    findings.Location{FilePath: "src/routes/assistant.js", StartLine: 9},
		Message:     `Untrusted input (http_body from "req.body" used directly) reaches prompt_injection sink`,
		Fingerprint: "fp-taint",
		Metadata: map[string]string{
			"vuln_class": "prompt_injection", "source_kind": "http_body", "sink": "openai.chat.completions.create",
		},
		Exploitability: "POTENTIAL",
	}
}

// saasFindings mirrors the Express app the assessment was designed against:
// one package with many advisories, a few with one or two, a taint flow and
// three typosquatting suspicions.
func saasFindings() []findings.Finding {
	var ff []findings.Finding
	axiosFixes := []string{"1.12.0", "1.13.5", "1.15.0", "1.15.1", "1.16.0", "1.18.0", "1.20.0", "1.8.2"}
	for i := 0; i < 33; i++ {
		sev := findings.SeverityMedium
		if i%3 == 0 {
			sev = findings.SeverityHigh
		}
		ff = append(ff, dep("axios", "1.7.4", axiosFixes[i%len(axiosFixes)], sev, "fp-axios-"+string(rune('a'+i%26))+string(rune('a'+i/26))))
	}
	ff = append(ff,
		dep("body-parser", "1.20.3", "1.20.6", findings.SeverityLow, "fp-bp-1"),
		dep("body-parser", "1.20.3", "1.20.9", findings.SeverityHigh, "fp-bp-2"),
		dep("path-to-regexp", "0.1.12", "0.1.13", findings.SeverityHigh, "fp-ptr"),
		dep("qs", "6.13.0", "6.14.1", findings.SeverityLow, "fp-qs-1"),
		dep("qs", "6.13.0", "6.14.2", findings.SeverityLow, "fp-qs-2"),
		dep("qs", "6.13.0", "6.15.2", findings.SeverityMedium, "fp-qs-3"),
		dep("qs", "6.13.0", "6.16.0", findings.SeverityMedium, "fp-qs-4"),
		promptInjection(),
		typosquat("safer-buffer", "2.1.2", "fp-ts-1"),
		typosquat("openai", "4.77.0", "fp-ts-2"),
		typosquat("jws", "3.2.3", "fp-ts-3"),
	)
	return ff
}

func plan(t *testing.T, ff []findings.Finding) *attack.Plan {
	t.Helper()
	p, err := attack.BuildPlan(attack.PlanInput{Root: ".", Findings: ff})
	if err != nil {
		t.Fatal(err)
	}
	return p
}

func scopes(t *testing.T, only, skip string) nox.ScopeSet {
	t.Helper()
	s, err := nox.ResolveScopes(strings.Split(only, ","), strings.Split(skip, ","))
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// installedPlugins is the set measured in docs/plugin-defaults.md, the one a
// developer who has tried the marketplace is likely to have.
var installedPlugins = []string{
	"freshness", "nox/ai-eval", "nox/api-abuse", "nox/attack-surface",
	"nox/container", "nox/dast", "nox/depconfusion", "nox/grc",
	"nox/k8s-runtime", "nox/reachability", "nox/remediate",
	"nox/taint-analysis", "nox/threat-enrich", "nox/threat-model",
	"nox/triage-agent",
}

var undeclaredPlugins = nox.Degradation{
	Kind:     "plugin",
	Detail:   plugincap.UndeclaredDetail(installedPlugins),
	Impact:   "their findings are absent from this scan; add the ones you want to plugins.required in .nox.yaml",
	Advisory: true,
}

func invoiceLead(route, file string, line int) nox.Lead {
	return nox.Lead{
		Category: "authorization", RuleID: "AUTHZ-001", Route: route, FilePath: file, Line: line,
		Statement: "loads a record by a caller-supplied id with no visible ownership check",
		Test:      "Test it with two user accounts: request user A's record while signed in as user B.",
	}
}

func manyLeads(n int) []nox.Lead {
	out := make([]nox.Lead, 0, n)
	for i := 0; i < n; i++ {
		out = append(out, invoiceLead("GET /api/r"+strconv.Itoa(i)+"/:id", "src/routes/r"+strconv.Itoa(i)+".js", 10+i))
	}
	return out
}

// Leads are not findings: they add no issue, change no count, and under
// --verbose (limit 0) every one is listed.
func TestLeadsAreNotIssues(t *testing.T) {
	in := Input{Scope: nox.FullScope(), Leads: manyLeads(7)}
	r := Build(in)
	if len(r.Issues) != 0 || r.FindingCount != 0 {
		t.Fatalf("leads became issues: %+v", r.Issues)
	}
	var buf bytes.Buffer
	if err := Render(&buf, r, RenderOptions{Limit: 0}); err != nil {
		t.Fatal(err)
	}
	if got := strings.Count(buf.String(), "  - Authorization: "); got != 7 {
		t.Errorf("verbose lists %d leads, want 7", got)
	}
	if !strings.Contains(buf.String(), "No issues found in what was checked.") {
		t.Errorf("a scan with only leads must still say no issues were found:\n%s", buf.String())
	}
}

func TestRenderGolden(t *testing.T) {
	saas := saasFindings()

	many := []findings.Finding{
		dep("lodash", "3.10.0", "4.17.21", findings.SeverityCritical, "fp-lodash"),
		dep("left-pad", "1.0.0", "", findings.SeverityHigh, "fp-leftpad"),
		{
			RuleID: "SEC-001", Severity: findings.SeverityHigh, Confidence: findings.ConfidenceHigh,
			Location: findings.Location{FilePath: "config/prod.env", StartLine: 3},
			Message:  "AWS access key ID", Fingerprint: "fp-sec-1", Exploitability: "POTENTIAL",
		},
		{
			RuleID: "IAC-001", Severity: findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
			Location: findings.Location{FilePath: "Dockerfile", StartLine: 1},
			Message:  "Container image uses the latest tag. Pin a digest.", Fingerprint: "fp-iac-1", Exploitability: "POTENTIAL",
		},
	}
	// A fix exists but nox fix cannot drive maven: say what to upgrade to,
	// not "no fix". And a workspace upgrade names its directory.
	maven := dep("org.yaml:snakeyaml", "1.33", "2.0", findings.SeverityHigh, "fp-maven")
	maven.Location.FilePath = "services/api/pom.xml"
	maven.Metadata["ecosystem"] = "maven"
	web := dep("axios", "1.7.4", "1.8.2", findings.SeverityMedium, "fp-web-axios")
	web.Location.FilePath = "apps/web/package-lock.json"
	many = append(many, maven, web)
	for i, file := range []string{"a.tf", "b.tf", "c.tf", "d.tf", "e.tf"} {
		many = append(many, findings.Finding{
			RuleID: "IAC-002", Severity: findings.SeverityLow, Confidence: findings.ConfidenceMedium,
			Location: findings.Location{FilePath: file, StartLine: 10 + i},
			Message:  "Bucket has no access logging", Fingerprint: "fp-iac2-" + file, Exploitability: "CONFIRMED",
		})
	}

	tests := []struct {
		name  string
		in    Input
		limit int
	}{
		{
			name: "saas",
			in: Input{
				Findings: saas, Plan: plan(t, saas), Scope: nox.FullScope(),
				Degradations: []nox.Degradation{undeclaredPlugins}, Packages: 123,
				Target: ".", FindingsPath: "./findings.json",
			},
			limit: DefaultLimit,
		},
		{
			name:  "saas_verbose",
			in:    Input{Findings: saas, Plan: plan(t, saas), Scope: nox.FullScope(), Packages: 123, Target: ".", FindingsPath: "./findings.json"},
			limit: 0,
		},
		{
			name: "clean",
			in: Input{
				Scope: nox.FullScope(), Plan: plan(t, nil), Packages: 0, Target: ".", FindingsPath: "./findings.json",
			},
			limit: DefaultLimit,
		},
		{
			name: "scoped_offline_degraded",
			in: Input{
				Findings: many, Scope: scopes(t, "", "ai,data"), Offline: true, Packages: 12,
				Degradations: []nox.Degradation{
					{Kind: "lockfile_parse", Detail: "yarn.lock: unexpected token", Impact: "dependencies declared there were not checked"},
					{Kind: "lockfile_parse", Detail: "poetry.lock: unexpected token", Impact: "dependencies declared there were not checked"},
				},
				Target: "app", FindingsPath: "out/findings.json",
			},
			limit: DefaultLimit,
		},
		{
			// Grounded in the AI inventory, not a finding: the agent is named,
			// and the command carries --inventory so it rebuilds the same plan.
			name: "agent_inventory",
			in: Input{
				Scope: nox.FullScope(), Packages: 3, Target: ".", FindingsPath: "./findings.json",
				InventoryPath: "./ai.inventory.json",
				Plan: &attack.Plan{Hypotheses: []attack.Hypothesis{
					{
						ScenarioID: "TOOL-UNAUTH", Objective: "coerce the agent into invoking a tool the request was not authorized to use",
						Path: []attack.PathStep{{Kind: attack.StepEntryPoint, Label: "untrusted request field"}, {Kind: attack.StepAgent, Label: "tools.py"}},
					},
					{
						ScenarioID: "EXFIL-FS-NET", Objective: "move a filesystem secret to a network sink under attacker control",
						Path: []attack.PathStep{{Kind: attack.StepEntryPoint, Label: "untrusted request field"}, {Kind: attack.StepAgent, Label: "tools.py"}},
					},
				}},
			},
			limit: DefaultLimit,
		},
		{
			// AUTHZ-001 not enabled: the route is a lead, listed under
			// verification and never counted as an issue, and coverage says
			// what was read without claiming authorization was checked.
			name: "authz_lead",
			in: Input{
				Findings: []findings.Finding{promptInjection()}, Plan: plan(t, []findings.Finding{promptInjection()}),
				Scope: nox.FullScope(), Packages: 123, Target: ".", FindingsPath: "./findings.json",
				Leads:      []nox.Lead{invoiceLead("GET /api/invoices/:id", "src/routes/invoices.js", 14)},
				LeadChecks: []string{"authorization (Express, Fastify, Flask, FastAPI routes; leads only)"},
			},
			limit: DefaultLimit,
		},
		{
			// More leads than the limit: the first five, then a count.
			name: "authz_leads_capped",
			in: Input{
				Scope: nox.FullScope(), Packages: 3, Target: ".", FindingsPath: "./findings.json",
				Leads:      manyLeads(7),
				LeadChecks: []string{"authorization (Express, Fastify, Flask, FastAPI routes; leads only)"},
			},
			limit: DefaultLimit,
		},
		{
			name: "no_findings_json",
			in: Input{
				Findings: []findings.Finding{dep("express", "4.17.0", "5.0.0", findings.SeverityHigh, "fp-express")},
				Scope:    nox.FullScope(), Packages: 1, Target: ".",
			},
			limit: DefaultLimit,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			if err := Render(&buf, Build(tc.in), RenderOptions{Limit: tc.limit}); err != nil {
				t.Fatal(err)
			}
			golden := filepath.Join("testdata", tc.name+".golden")
			if *update {
				if err := os.WriteFile(golden, buf.Bytes(), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			want, err := os.ReadFile(golden)
			if err != nil {
				t.Fatalf("%v (run go test ./core/assess -update to create it)", err)
			}
			if got := buf.String(); got != string(want) {
				t.Errorf("assessment differs from %s\n--- got ---\n%s\n--- want ---\n%s", golden, got, want)
			}
		})
	}
}

// The vision: nobody has to know which component performs a check. The
// assessment names capabilities; a plugin name appearing in it is the defect.
func TestNotCheckedNamesCapabilitiesNotPlugins(t *testing.T) {
	r := Build(Input{Findings: saasFindings(), Scope: nox.FullScope(), Degradations: []nox.Degradation{undeclaredPlugins}})
	var b bytes.Buffer
	if err := Render(&b, r, RenderOptions{Limit: DefaultLimit}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, n := range installedPlugins {
		// "freshness" is also an ordinary word, and the capability is allowed
		// to use it; the registry-qualified names are what must not appear.
		if n != "freshness" && strings.Contains(out, n) {
			t.Errorf("the assessment names plugin %q:\n%s", n, out)
		}
	}
	// plugins.required is the config key the one action points at; nothing else
	// in the account may talk about plugins.
	if strings.Contains(strings.ReplaceAll(out, "plugins.required", ""), "plugin") {
		t.Errorf("the assessment says \"plugin\":\n%s", out)
	}
	for _, c := range []string{"API abuse patterns (rate limiting, error detail)", "exposed endpoints and admin or debug routes", "dependency-confusion exposure"} {
		if !strings.Contains(out, c) {
			t.Errorf("an unchecked capability %q is not named:\n%s", c, out)
		}
	}
	// Live testing is its own line: it needs authorization, which an optional
	// static check does not.
	if !strings.Contains(out, "Live testing did not run (adversarial prompts against a live chat endpoint, inspecting running Kubernetes workloads and probing a running web application)") {
		t.Errorf("live testing is not stated as such:\n%s", out)
	}
}

// A plugin whose check core performs, one measured to hurt, and one that only
// annotates are not gaps. Listing them as "Not checked" would tell the reader
// container configuration was skipped (core checks it) and invite them to turn
// on a reachability that calls a transitive dependency a likely false positive.
func TestCoveredRetiredAndAdjunctPluginsAreNotListedAsGaps(t *testing.T) {
	d := nox.Degradation{
		Kind:     "plugin",
		Detail:   plugincap.UndeclaredDetail([]string{"nox/container", "nox/taint-analysis", "nox/reachability", "nox/triage-agent", "nox/threat-model", "nox/threat-enrich", "nox/remediate", "nox/grc"}),
		Impact:   "their findings are absent from this scan",
		Advisory: true,
	}
	r := Build(Input{Findings: saasFindings(), Scope: nox.FullScope(), Degradations: []nox.Degradation{d}})
	for _, l := range r.NotChecked {
		t.Errorf("a plugin that leaves no gap produced a Not checked line: %+v", l)
	}
}

// What did not run stays accounted for in full, with names, for the machine
// outputs and --verbose. Only the assessment's wording is capability-shaped.
func TestDegradationDetailStillNamesEveryPlugin(t *testing.T) {
	for _, n := range installedPlugins {
		if !strings.Contains(undeclaredPlugins.Detail, n) {
			t.Errorf("the degradation no longer names %q", n)
		}
	}
	if !undeclaredPlugins.Advisory {
		t.Error("an unenabled plugin must stay an advisory degradation, not a failure")
	}
}

// A degradation another producer wrote, in a shape plugincap cannot read, must
// not vanish from the assessment.
func TestUnreadablePluginDegradationFallsBackToAGenericLine(t *testing.T) {
	d := nox.Degradation{Kind: "plugin", Detail: "something else entirely", Impact: "x", Advisory: true}
	r := Build(Input{Findings: saasFindings(), Scope: nox.FullScope(), Degradations: []nox.Degradation{d}})
	if len(r.NotChecked) != 1 || !strings.Contains(r.NotChecked[0].Summary, "Optional checks are installed but not enabled") {
		t.Fatalf("NotChecked = %+v", r.NotChecked)
	}
}

// An internal degradation kind is not a sentence. "A check did not complete
// (generated_report)" put a Go identifier in front of a first-time user.
func TestEveryAdvisoryKindHasAHeadline(t *testing.T) {
	d := nox.Degradation{Kind: "generated_report", Detail: "6 file(s) not scanned", Impact: "a nox report holds nox's own text", Advisory: true}
	r := Build(Input{Findings: saasFindings(), Scope: nox.FullScope(), Degradations: []nox.Degradation{d}})
	if len(r.NotChecked) != 1 || strings.Contains(r.NotChecked[0].Summary, "generated_report") {
		t.Fatalf("NotChecked = %+v", r.NotChecked)
	}
}

// One upgrade line per action the planner takes, standing for every advisory
// that action resolves: 33 axios findings are one thing to do, not 33.
func TestIssuesFollowTheFixPlanner(t *testing.T) {
	r := Build(Input{Findings: saasFindings(), Scope: nox.FullScope()})
	var upgrades []Issue
	for _, is := range r.Issues {
		if is.Kind == KindUpgrade {
			upgrades = append(upgrades, is)
		}
	}
	if len(upgrades) != 4 {
		t.Fatalf("want the 4 moves nox fix --dry-run plans, got %d: %+v", len(upgrades), upgrades)
	}
	if !strings.HasPrefix(upgrades[0].Summary, "Upgrade axios 1.7.4 -> 1.20.0: fixes 33 known vulnerabilities") {
		t.Errorf("axios should lead with all 33 advisories under one upgrade, got %q", upgrades[0].Summary)
	}
	total := 0
	for _, is := range r.Issues {
		total += is.Findings
	}
	if total != len(saasFindings()) {
		t.Errorf("every finding must be accounted for exactly once: issues cover %d of %d", total, len(saasFindings()))
	}
}

// A clean scan must say what it checked: "0 issues" from a scan that looked at
// nothing reads exactly like one that looked everywhere.
func TestCleanScanStatesWhatWasChecked(t *testing.T) {
	var buf bytes.Buffer
	if err := Render(&buf, Build(Input{Scope: nox.FullScope()}), RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	for _, want := range []string{"No issues found in what was checked.", "Checks completed: secrets, application code, dependencies"} {
		if !strings.Contains(out, want) {
			t.Errorf("clean assessment is missing %q:\n%s", want, out)
		}
	}
}

// Same input, same text: no clock, no map order.
func TestRenderIsDeterministic(t *testing.T) {
	in := Input{Findings: saasFindings(), Plan: plan(t, saasFindings()), Scope: nox.FullScope(), Packages: 123}
	var first bytes.Buffer
	if err := Render(&first, Build(in), RenderOptions{}); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 20; i++ {
		var again bytes.Buffer
		if err := Render(&again, Build(in), RenderOptions{}); err != nil {
			t.Fatal(err)
		}
		if again.String() != first.String() {
			t.Fatalf("render %d differs from the first", i)
		}
	}
}

// A hypothesis grounded only in a finding the user filtered out (a threshold)
// must not be recommended: the assessment talks about what it shows.
func TestVerificationOnlyForReportedFindings(t *testing.T) {
	all := saasFindings()
	var deps []findings.Finding
	for i := range all {
		if all[i].RuleID != "TAINT-AI-001" {
			deps = append(deps, all[i])
		}
	}
	r := Build(Input{Findings: deps, Plan: plan(t, all), Scope: nox.FullScope()})
	if len(r.Verify) != 0 {
		t.Errorf("no reported finding grounds a hypothesis, got %+v", r.Verify)
	}
}

// A mirror-backed answer is a specific, blocking limit, not the generic
// "answered only in part"; a different partial answer in the same scan keeps
// its own line.
func TestMirrorAnswerIsASpecificBlockingLimit(t *testing.T) {
	mirror := nox.Degradation{
		Kind:   "intel_incomplete",
		Detail: "nox-intelligence answered 1 package(s) incompletely: npm/a@1 (degraded: " + osvsource.MirrorOnlyNote + ")",
		Impact: "x",
	}
	truncated := nox.Degradation{
		Kind:   "intel_incomplete",
		Detail: "nox-intelligence answered 1 package(s) incompletely: npm/b@1 (incomplete: pagination stopped)",
		Impact: "an empty or short advisory list is not proof",
	}
	r := Build(Input{Findings: saasFindings(), Scope: nox.FullScope(), Degradations: []nox.Degradation{mirror, truncated}})
	var sawMirror, sawGeneric bool
	for _, l := range r.NotChecked {
		switch {
		case strings.Contains(l.Summary, "mirror; live OSV unavailable"):
			sawMirror = true
			if !l.Blocking {
				t.Error("the mirror limit must block")
			}
		case strings.Contains(l.Summary, "only in part"):
			sawGeneric = true
		}
	}
	if !sawMirror || !sawGeneric {
		t.Fatalf("NotChecked = %+v", r.NotChecked)
	}
}

// advisory_detail has its own headline: the generic "A check did not complete
// (advisory_detail)" fallback names a kind no reader knows and says nothing
// about what is at risk (a severity gate).
func TestAdvisoryDetailDegradationHasAHeadline(t *testing.T) {
	d := nox.Degradation{
		Kind:   "advisory_detail",
		Detail: "2 findings kept a default severity (osv: GHSA-aaaa, GHSA-bbbb)",
		Impact: "a severity gate may not see them",
	}
	r := Build(Input{Findings: saasFindings(), Scope: nox.FullScope(), Degradations: []nox.Degradation{d}})
	var got *Limit
	for i := range r.NotChecked {
		if strings.Contains(r.NotChecked[i].Summary, "severities") {
			got = &r.NotChecked[i]
		}
	}
	if got == nil {
		t.Fatalf("no advisory_detail headline in %+v", r.NotChecked)
	}
	if !got.Blocking || strings.Contains(got.Summary, "advisory_detail") {
		t.Errorf("headline = %+v; want a blocking, plain-language line", *got)
	}
}
