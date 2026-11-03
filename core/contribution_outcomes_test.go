package core

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/git"
	"github.com/nox-hq/nox/core/intel"
)

// gitRepo makes a repository with two commits and returns its directory.
func gitRepo(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, args := range [][]string{
		{"init", "-q", "-b", "main"},
		{"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "first"},
		{"-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "second"},
	} {
		gitIn(t, dir, args...)
	}
	return dir
}

func outcomeFindings() []findings.Finding {
	return []findings.Finding{{RuleID: "VULN-001", Location: findings.Location{FilePath: "go.mod"},
		Metadata: map[string]string{"ecosystem": "go", "package": "golang.org/x/net", "version": "v0.6.0",
			"vuln_id": "GO-2023-1571", "applicability": "undetermined", "dependency_imported": "true"}}}
}

// outcomeCfg is a config with contribution and outcomes on and both sets of
// terms accepted; each test removes the gate it is about.
func outcomeCfg(t *testing.T, d *contractDouble) *ScanConfig {
	t.Helper()
	cfg := consentCfg(t, d)
	cfg.Scan.Intelligence.Outcomes = true
	sp := cfg.Scan.Intelligence.ReporterSaltPath
	if err := intel.RecordConsent(sp, "2026-11-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if err := intel.RecordOutcomeConsent(sp, "2026-11-03T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	return cfg
}

func (d *contractDouble) outcomeBodies() []map[string]any {
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []map[string]any
	for i, p := range d.paths {
		if p == "/v1/outcomes" {
			out = append(out, d.bodies[i])
		}
	}
	return out
}

func TestOutcomes_SentOncePerScanWithAStablePseudonym(t *testing.T) {
	d := newContractDouble(t)
	cfg := outcomeCfg(t, d)
	repo := gitRepo(t)
	for i := 0; i < 2; i++ {
		deg := &degrade.Degradations{}
		contributeOutcomes(context.Background(), cfg, ScanOptions{ContributeObservations: true, ToolVersion: "1.58.0"},
			repo, outcomeFindings(), deg)
		if got := degradationText(deg); got != "" {
			t.Fatalf("scan %d degraded: %s", i, got)
		}
	}
	bodies := d.outcomeBodies()
	if len(bodies) != 2 {
		t.Fatalf("%d outcome reports for two scans", len(bodies))
	}
	if bodies[0]["project"] != bodies[1]["project"] || len(bodies[0]["project"].(string)) != 64 {
		t.Fatalf("pseudonym not stable: %v vs %v", bodies[0]["project"], bodies[1]["project"])
	}
	fs := bodies[0]["findings"].([]any)
	if len(fs) != 1 || fs[0].(map[string]any)["imported"] != "yes" {
		t.Fatalf("findings = %v", fs)
	}
	// Neither the repository's path nor its root commit leaves.
	root, err := git.RootCommit(repo)
	if err != nil {
		t.Fatal(err)
	}
	for _, b := range bodies {
		raw, _ := json.Marshal(b)
		for _, leak := range []string{root, root[:12], repo, filepath.Base(repo)} {
			if strings.Contains(string(raw), leak) {
				t.Errorf("the outcome report carries %q: %s", leak, raw)
			}
		}
	}
}

func TestOutcomes_EveryGateSendsNothingAndSaysWhy(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(t *testing.T, cfg *ScanConfig) string // returns the target
		says   string
	}{
		{"outcomes without contribute", func(t *testing.T, c *ScanConfig) string {
			c.Scan.Intelligence.Contribute = false
			return gitRepo(t)
		}, "scan.intelligence.contribute is not"},
		{"outcome terms not accepted", func(t *testing.T, c *ScanConfig) string {
			_ = intel.WithdrawOutcomeConsent(c.Scan.Intelligence.ReporterSaltPath)
			return gitRepo(t)
		}, "has not accepted the outcome terms"},
		{"outcome terms stale", func(t *testing.T, c *ScanConfig) string {
			p := intel.OutcomeConsentPath(c.Scan.Intelligence.ReporterSaltPath)
			_ = os.WriteFile(p, []byte(`{"terms_version":"outcomes-1999-01","accepted_at":"x"}`), 0o600)
			return gitRepo(t)
		}, "outcome reports are paused"},
		{"not a repository", func(t *testing.T, _ *ScanConfig) string { return t.TempDir() }, "no outcome report was sent"},
		{"shallow clone", func(t *testing.T, _ *ScanConfig) string {
			clone := filepath.Join(t.TempDir(), "shallow")
			gitIn(t, t.TempDir(), "clone", "-q", "--depth", "1", "file://"+gitRepo(t), clone)
			return clone
		}, "fetch-depth: 0"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := newContractDouble(t)
			cfg := outcomeCfg(t, d)
			target := tc.mutate(t, cfg)
			deg := &degrade.Degradations{}
			contributeOutcomes(context.Background(), cfg, ScanOptions{ContributeObservations: true}, target, outcomeFindings(), deg)
			if n := len(d.outcomeBodies()); n != 0 {
				t.Fatalf("%d outcome report(s) sent", n)
			}
			if got := degradationText(deg); !strings.Contains(got, tc.says) {
				t.Errorf("degradation %q does not say %q", got, tc.says)
			}
		})
	}
}

// Off by default, and a scan that was not asked to contribute (nox intel
// preview) never sends one, whatever the config says.
func TestOutcomes_OffUnlessAskedForTwice(t *testing.T) {
	d := newContractDouble(t)
	cfg := outcomeCfg(t, d)
	repo := gitRepo(t)
	contributeOutcomes(context.Background(), cfg, ScanOptions{ContributeObservations: false}, repo, outcomeFindings(), &degrade.Degradations{})
	cfg.Scan.Intelligence.Outcomes = false
	contributeOutcomes(context.Background(), cfg, ScanOptions{ContributeObservations: true}, repo, outcomeFindings(), &degrade.Degradations{})
	if n := d.requests(); n != 0 {
		t.Fatalf("%d request(s) without both the option and the config", n)
	}
}
