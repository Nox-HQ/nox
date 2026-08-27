package core

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/findings"
)

// contributionProbe returns a server that counts observation submissions, and
// a scan config pointed at it with contribution enabled in config.
func contributionProbe(t *testing.T) (*httptest.Server, *atomic.Int32, *ScanConfig) {
	t.Helper()
	var posts atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/v1/observations" {
			posts.Add(1)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)

	cfg := &ScanConfig{}
	cfg.Scan.Intelligence.Endpoint = srv.URL
	cfg.Scan.Intelligence.Contribute = true
	cfg.Scan.Intelligence.ReporterSaltPath = filepath.Join(t.TempDir(), "salt")
	return srv, &posts, cfg
}

// vulnFindingsForContribution returns one eligible dependency finding.
func vulnFindingsForContribution() []findings.Finding {
	return []findings.Finding{{
		RuleID:   "VULN-001",
		Location: findings.Location{FilePath: "package-lock.json", StartLine: 1},
		Message:  "Known vulnerability in lodash",
		Metadata: map[string]string{
			"ecosystem": "npm", "package": "lodash",
			"version": "4.17.15", "fixed_in": "4.17.21",
		},
	}}
}

// Scanning must not transmit unless the caller asked for it. Deriving is pure
// computation; transmitting is not, and a transmission that rides along with
// "run a scan" happens in places nobody intended — it fired from
// `nox intel preview`, whose whole purpose is to show what would be sent
// without sending it.
func TestContribute_RequiresCallerOptIn(t *testing.T) {
	_, posts, cfg := contributionProbe(t)

	fs := vulnFindingsForContribution()

	// Config says yes, caller did not ask: silence.
	contributeObservations(context.Background(), cfg, ScanOptions{},
		fs, &degrade.Degradations{})
	if n := posts.Load(); n != 0 {
		t.Errorf("%d observations were sent without the caller opting in", n)
	}

	// Caller asks: transmitted.
	contributeObservations(context.Background(), cfg,
		ScanOptions{ContributeObservations: true}, fs, &degrade.Degradations{})
	if n := posts.Load(); n == 0 {
		t.Error("no observations were sent when both gates were open")
	}
}

// The config gate is independent: a caller opting in cannot contribute on
// behalf of an installation that never enabled it.
func TestContribute_RequiresConfigOptIn(t *testing.T) {
	_, posts, cfg := contributionProbe(t)
	cfg.Scan.Intelligence.Contribute = false

	contributeObservations(context.Background(), cfg,
		ScanOptions{ContributeObservations: true},
		vulnFindingsForContribution(), &degrade.Degradations{})

	if n := posts.Load(); n != 0 {
		t.Errorf("%d observations were sent although the config disabled contribution", n)
	}
}

// Querying an endpoint is not consent to contribute to it. A lookup already
// transmits (ecosystem, package, version) for every dependency, so if querying
// implied contributing then "contribute: false" would be a lie for anyone with
// an endpoint set.
func TestContribute_QueryingIsNotContributing(t *testing.T) {
	_, posts, cfg := contributionProbe(t)
	cfg.Scan.Intelligence.Contribute = false // endpoint still set

	contributeObservations(context.Background(), cfg,
		ScanOptions{ContributeObservations: true},
		vulnFindingsForContribution(), &degrade.Degradations{})

	if n := posts.Load(); n != 0 {
		t.Errorf("configuring an endpoint caused %d observations to be sent", n)
	}
}

// A contribution that cannot complete is recorded, never propagated: a scan
// that failed because an upload did would make opting in actively hostile.
func TestContribute_FailureIsRecordedNotPropagated(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	cfg := &ScanConfig{}
	cfg.Scan.Intelligence.Endpoint = srv.URL
	cfg.Scan.Intelligence.Contribute = true
	cfg.Scan.Intelligence.ReporterSaltPath = filepath.Join(t.TempDir(), "salt")

	deg := &degrade.Degradations{}
	contributeObservations(context.Background(), cfg,
		ScanOptions{ContributeObservations: true}, vulnFindingsForContribution(), deg)

	var found bool
	for _, d := range deg.Items() {
		if d.Kind == degrade.IntelContribution {
			found = true
		}
	}
	if !found {
		t.Error("a failed contribution was not recorded as a degradation")
	}
}
