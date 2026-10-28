package core

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/nox-hq/nox-core/degrade"
	"github.com/nox-hq/nox/core/intel"
)

// contractDouble implements the NOX Intelligence schema-2 intake contract
// (nox-intelligence docs/contributions.md) closely enough to refuse what the
// real service refuses, and records every request of any path.
type contractDouble struct {
	mu     sync.Mutex
	paths  []string
	bodies []map[string]any
	srv    *httptest.Server
}

func newContractDouble(t *testing.T) *contractDouble {
	t.Helper()
	d := &contractDouble{}
	d.srv = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		d.mu.Lock()
		d.paths = append(d.paths, r.URL.Path)
		d.bodies = append(d.bodies, m)
		d.mu.Unlock()
		if r.URL.Path == "/v1/observations" {
			if m["schema_version"] != float64(2) || m["consent_version"] != "2026-10" {
				w.WriteHeader(http.StatusForbidden)
				return
			}
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(d.srv.Close)
	return d
}

func (d *contractDouble) requests() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return len(d.paths)
}

func consentCfg(t *testing.T, d *contractDouble) *ScanConfig {
	t.Helper()
	cfg := &ScanConfig{}
	cfg.Scan.Intelligence.Endpoint = d.srv.URL
	cfg.Scan.Intelligence.Contribute = true
	cfg.Scan.Intelligence.ReporterSaltPath = filepath.Join(t.TempDir(), "salt")
	return cfg
}

// Contribute:true is project config. It does not speak for the machine: with no
// recorded acceptance nothing is derived, no salt is created, no request is
// made, and the scan says why.
func TestContribute_NoRecordedConsentSendsNothingAndSaysSo(t *testing.T) {
	d := newContractDouble(t)
	cfg := consentCfg(t, d)
	deg := &degrade.Degradations{}

	contributeObservations(context.Background(), cfg, ScanOptions{ContributeObservations: true},
		vulnFindingsForContribution(), deg)

	if n := d.requests(); n != 0 {
		t.Fatalf("%d request(s) made without consent", n)
	}
	if got := degradationText(deg); !strings.Contains(got, "has not accepted") {
		t.Errorf("the scan did not say contribution was held back: %q", got)
	}
	if _, found, _ := intel.ExistingIdentity(cfg.Scan.Intelligence.ReporterSaltPath); found {
		t.Error("a reporter identity was minted although nothing could be sent")
	}
}

// A terms change pauses contribution until re-accepted, and says so.
func TestContribute_StaleTermsPauseAndSaySo(t *testing.T) {
	d := newContractDouble(t)
	cfg := consentCfg(t, d)
	sp := cfg.Scan.Intelligence.ReporterSaltPath
	writeConsentFile(t, sp, `{"terms_version":"2025-01","accepted_at":"2025-01-01T00:00:00Z"}`)
	deg := &degrade.Degradations{}

	contributeObservations(context.Background(), cfg, ScanOptions{ContributeObservations: true},
		vulnFindingsForContribution(), deg)

	if n := d.requests(); n != 0 {
		t.Fatalf("%d request(s) made under superseded terms", n)
	}
	got := degradationText(deg)
	if !strings.Contains(got, "2025-01") || !strings.Contains(got, intel.TermsVersion) || !strings.Contains(got, "paused") {
		t.Errorf("pause message must name both versions: %q", got)
	}
}

// With consent recorded, the body is the v2 contract: schema_version 2, the
// accepted terms version, and a verifier that is the SHA-256 of a deletion key
// that is itself never sent.
func TestContribute_SendsSchema2WithConsentAndVerifier(t *testing.T) {
	d := newContractDouble(t)
	cfg := consentCfg(t, d)
	sp := cfg.Scan.Intelligence.ReporterSaltPath
	if err := intel.RecordConsent(sp, "2026-10-25T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	deg := &degrade.Degradations{}

	contributeObservations(context.Background(), cfg, ScanOptions{ContributeObservations: true},
		vulnFindingsForContribution(), deg)

	if d.requests() != 1 {
		t.Fatalf("want 1 request, got %d (%q)", d.requests(), degradationText(deg))
	}
	if got := degradationText(deg); got != "" {
		t.Errorf("unexpected degradation: %q", got)
	}
	body := d.bodies[0]
	key, err := intel.DeletionKey(sp)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256([]byte(key))
	if body["deletion_verifier"] != hex.EncodeToString(sum[:]) {
		t.Errorf("deletion_verifier is not sha256(deletion key): %v", body["deletion_verifier"])
	}
	raw, _ := json.Marshal(body)
	if strings.Contains(string(raw), key) {
		t.Error("the deletion key itself was transmitted with an observation")
	}
}

// Offline-first: with contribution off at either gate, no request of any kind
// is made, consent or not.
func TestContribute_OffMeansNoRequestOfAnyKind(t *testing.T) {
	for name, tc := range map[string]struct {
		contribute, caller bool
	}{
		"config off":        {false, true},
		"caller not asking": {true, false},
	} {
		t.Run(name, func(t *testing.T) {
			d := newContractDouble(t)
			cfg := consentCfg(t, d)
			cfg.Scan.Intelligence.Contribute = tc.contribute
			if err := intel.RecordConsent(cfg.Scan.Intelligence.ReporterSaltPath, "2026-10-25T00:00:00Z"); err != nil {
				t.Fatal(err)
			}
			deg := &degrade.Degradations{}
			contributeObservations(context.Background(), cfg,
				ScanOptions{ContributeObservations: tc.caller}, vulnFindingsForContribution(), deg)
			if n := d.requests(); n != 0 {
				t.Errorf("%d request(s) with contribution off", n)
			}
			if got := degradationText(deg); got != "" {
				t.Errorf("a scan with contribution off must say nothing about it: %q", got)
			}
		})
	}
}

func degradationText(deg *degrade.Degradations) string {
	var b strings.Builder
	for _, d := range deg.Items() {
		b.WriteString(d.Detail + " | " + d.Impact + "\n")
	}
	return b.String()
}

func writeConsentFile(t *testing.T, saltPath, content string) {
	t.Helper()
	if err := os.WriteFile(intel.ConsentPath(saltPath), []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
