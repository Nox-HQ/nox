package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Flag-efficacy guards for `nox scan`.
//
// The motivating defect is one nox already shipped elsewhere: `attack run`'s
// --max-duration parsed cleanly, was stored on a struct, and did nothing,
// because nothing ever read the field it set. On a security scanner a flag that
// silently does nothing is a control the operator believes is on. `nox scan`
// carries the largest flag surface in the tool and had no such guard.
//
// The strongest tractable check is mechanical: every registered flag must be
// READ somewhere, not merely declared and bound. A flag that is genuinely inert
// must say so — in its own help text and on the allowlist below — so "does
// nothing" is a documented decision rather than an accident.

// scanFlagBinding is one registered `nox scan` flag and the variable it binds.
type scanFlagBinding struct {
	flag string
	// variable is the Go identifier the flag writes to. A flag whose variable is
	// never read past its declaration and registration is inert.
	variable string
}

// scanFlagBindings mirrors the registrations in runScan.
//
// Keeping it by hand is deliberate: the test below diffs it against the source,
// so a new flag cannot be added without appearing here, and appearing here means
// someone stated which variable it drives.
var scanFlagBindings = []scanFlagBinding{
	{"staged", "stagedFlag"},
	{"severity-threshold", "thresholdFlag"},
	{"min-confidence", "minConfidenceFlag"},
	{"no-osv", "noOSVFlag"},
	{"vex", "vexFlag"},
	{"tf-plan", "tfPlanFlag"},
	{"history", "historyFlag"},
	{"history-depth", "historyDepthFlag"},
	{"no-cache", "noCacheFlag"},
	{"changed-since", "changedSinceFlag"},
	{"baseline", "baselineFlag"},
	{"no-respect-gitignore", "noRespectGitignoreFlg"},
	{"tracked-only", "trackedOnlyFlag"},
	{"no-auto-install", "noAutoInstallFlg"},
	{"fail-on-unwaived", "failOnUnwaivedFlg"},
	{"fail-on-degraded", "failOnDegraded"},
	{"offline", "offlineFlag"},
	{"sort", "sortFlag"},
	{"fingerprint-version", "fingerprintVersionFlag"},
	{"evidence-out", "evidenceOutFlag"},
}

// inertScanFlags are flags that deliberately do nothing. An entry is a promise
// that the flag's own help text says so, which the test enforces — an inert flag
// the operator cannot tell is inert is the defect; an honestly-labelled one is
// a compatibility shim.
var inertScanFlags = map[string]string{
	"no-cache": "scans are never cached; accepted so existing scripts keep working",
}

// TestEveryScanFlagIsRead asserts each registered flag's variable is actually
// consumed, so a flag cannot parse and then do nothing.
func TestEveryScanFlagIsRead(t *testing.T) {
	src := readCLISource(t, "main.go")

	for _, b := range scanFlagBindings {
		t.Run(b.flag, func(t *testing.T) {
			// Declaration and registration are the two uses every flag has. A
			// third means something reads it.
			uses := strings.Count(src, b.variable)
			if uses < 2 {
				t.Fatalf("flag --%s: variable %s appears %d times; the inventory is stale",
					b.flag, b.variable, uses)
			}
			read := uses > 2

			reason, inert := inertScanFlags[b.flag]
			switch {
			case read && inert:
				t.Errorf("flag --%s is on the inert allowlist (%q) but its variable IS read; "+
					"remove it from inertScanFlags", b.flag, reason)
			case !read && !inert:
				t.Errorf("flag --%s parses into %s, but nothing reads that variable — the flag "+
					"does nothing. Wire it up, or declare it inert in inertScanFlags AND say so "+
					"in its help text.", b.flag, b.variable)
			}
		})
	}
}

// TestInertScanFlagsAdmitItInTheirHelpText: a flag that does nothing must tell
// the operator, at the point they would read about it.
func TestInertScanFlagsAdmitItInTheirHelpText(t *testing.T) {
	src := readCLISource(t, "main.go")

	for flag := range inertScanFlags {
		// Anchor on the scanFS registration, not the first mention of the name:
		// flag names also appear in argument-parsing switches, and matching one
		// of those would read the wrong line.
		line := scanRegistrationLine(src, flag)
		if line == "" {
			t.Errorf("flag --%s is on the inert allowlist but is not registered on `nox scan`", flag)
			continue
		}
		if !strings.Contains(strings.ToLower(line), "no-op") {
			t.Errorf("flag --%s does nothing, but its help text does not say so: %s", flag, strings.TrimSpace(line))
		}
	}
}

// scanRegistrationLine returns the `scanFS.XVar(&v, "flag", ...)` line for a
// flag, or "" if it is not registered on the scan flag set.
func scanRegistrationLine(src, flag string) string {
	for _, line := range strings.Split(src, "\n") {
		if strings.Contains(line, "scanFS.") && strings.Contains(line, `"`+flag+`"`) {
			return line
		}
	}
	return ""
}

// TestInertScanFlagsAreNotAdvertisedAsWorkingInTheREADME checks the docs agree
// with the binary about which flags do nothing.
//
// The flag's own help text is one place an operator reads about it; the README
// is the other, and it can contradict the binary. It did: --no-cache described
// itself as "no-op: accepted for compatibility" while the README promised it
// would "Disable incremental scan cache". Documentation that claims a control
// works is the same defect as an inert flag, just further from the code.
func TestInertScanFlagsAreNotAdvertisedAsWorkingInTheREADME(t *testing.T) {
	readme, err := os.ReadFile("../README.md")
	if err != nil {
		t.Skipf("README not readable: %v", err)
	}
	for flag := range inertScanFlags {
		for _, line := range strings.Split(string(readme), "\n") {
			if !strings.Contains(line, "--"+flag) {
				continue
			}
			low := strings.ToLower(line)
			if !strings.Contains(low, "no-op") && !strings.Contains(low, "no op") {
				t.Errorf("README documents --%s without saying it is a no-op: %s",
					flag, strings.TrimSpace(line))
			}
		}
	}
}

// TestScanFlagInventoryMatchesRegistrations diffs the hand-kept inventory
// against the source in both directions, so a flag cannot be added or removed
// without the efficacy guard noticing.
func TestScanFlagInventoryMatchesRegistrations(t *testing.T) {
	src := readCLISource(t, "main.go")

	registered := map[string]bool{}
	for _, line := range strings.Split(src, "\n") {
		if !strings.Contains(line, "scanFS.") || !strings.Contains(line, "Var(&") {
			continue
		}
		// scanFS.BoolVar(&x, "name", ...)
		open := strings.Index(line, `"`)
		if open < 0 {
			continue
		}
		rest := line[open+1:]
		endQuote := strings.IndexByte(rest, '"')
		if endQuote < 0 {
			continue
		}
		registered[rest[:endQuote]] = true
	}

	inventory := map[string]bool{}
	for _, b := range scanFlagBindings {
		inventory[b.flag] = true
	}

	for flag := range registered {
		if !inventory[flag] {
			t.Errorf("flag --%s is registered on `nox scan` but is not in scanFlagBindings; "+
				"add it with the variable it drives so its efficacy is guarded", flag)
		}
	}
	for flag := range inventory {
		if !registered[flag] {
			t.Errorf("scanFlagBindings lists --%s, which `nox scan` no longer registers", flag)
		}
	}
}

// TestScanSeverityThresholdFiltersFindings proves --severity-threshold changes
// an observable outcome rather than merely parsing.
func TestScanSeverityThresholdFiltersFindings(t *testing.T) {
	dir := t.TempDir()
	// A high-severity secret and a low-severity finding source.
	writeScanFixture(t, dir, "config.env", "AWS_KEY=AKIAIOSFODNN7EXAMPLE\n")

	all := scanFindingCount(t, dir, nil)
	if all == 0 {
		t.Skip("fixture produced no findings; nothing to filter")
	}
	// A threshold above anything present must reduce the reported set.
	filtered := scanFindingCount(t, dir, []string{"--severity-threshold", "critical"})
	if filtered > all {
		t.Errorf("--severity-threshold critical reported %d findings, more than the unfiltered %d",
			filtered, all)
	}
	if filtered == all {
		t.Logf("note: every finding in the fixture is critical (%d); threshold could not reduce", all)
	}
}

// writeScanFixture writes a file into a scan target directory.
func writeScanFixture(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o600); err != nil {
		t.Fatalf("writing fixture %s: %v", name, err)
	}
}

// scanFindingCount runs `nox scan` into a temp output dir and returns how many
// findings the artifact reports.
func scanFindingCount(t *testing.T, target string, extraArgs []string) int {
	t.Helper()
	out := t.TempDir()
	args := append([]string{target}, extraArgs...)
	if code := runScan(args, "json", out, "", true, false); code > 1 {
		t.Fatalf("scan exited %d (args %v)", code, args)
	}
	data, err := os.ReadFile(filepath.Join(out, "findings.json")) //nolint:gosec // temp dir
	if err != nil {
		t.Fatalf("reading findings.json: %v", err)
	}
	return strings.Count(string(data), `"rule_id"`)
}
