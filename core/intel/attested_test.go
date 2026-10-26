package intel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/nox-hq/nox-core/evidence"
)

func TestClientWithTokenUsesTheAttestedRoute(t *testing.T) {
	var path, auth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path, auth = r.URL.Path, r.Header.Get("Authorization")
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	o := Observation{SchemaVersion: 2, ConsentVersion: TermsVersion, Fingerprint: "f", Ecosystem: "npm", Package: "p", ObservedAt: "2026-10-26T00:00:00Z"}

	NewClient(srv.URL, nil).Contribute(context.Background(), []Observation{o})
	if path != "/v1/observations" || auth != "" {
		t.Errorf("anonymous: %s %q", path, auth)
	}
	NewClient(srv.URL, nil).WithToken(" tok ").Contribute(context.Background(), []Observation{o})
	if path != "/v1/attested/observations" || auth != "Bearer tok" {
		t.Errorf("attested: %s %q", path, auth)
	}
}

func TestSubmitRunNeedsATokenAndAValidReport(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusAccepted)
		_, _ = w.Write([]byte(`{"scope":"reporter","attack_reporters":2}`))
	}))
	defer srv.Close()
	r := evidence.RunReport{SchemaVersion: 1, Fingerprint: strings.Repeat("a", 64), Exploitability: evidence.Prevented,
		Kind: evidence.KindHeuristic, Profile: "sandbox", TraceDigest: strings.Repeat("b", 64), ObservedAt: "2026-10-26T00:00:00Z"}

	if _, err := NewClient(srv.URL, nil).SubmitRun(context.Background(), r); err == nil || called {
		t.Fatalf("an unattested run was sent: err=%v called=%v", err, called)
	}
	bad := r
	bad.Profile = "safe"
	if _, err := NewClient(srv.URL, nil).WithToken("t").SubmitRun(context.Background(), bad); err == nil || called {
		t.Fatalf("an invalid run was sent: err=%v called=%v", err, called)
	}
	rc, err := NewClient(srv.URL, nil).WithToken("t").SubmitRun(context.Background(), r)
	if err != nil || rc.AttackReporter != 2 || rc.Scope != "reporter" {
		t.Fatalf("%+v %v", rc, err)
	}
}

func TestAttackTermsVersionPinsTheText(t *testing.T) {
	sum := sha256.Sum256([]byte(AttackTerms))
	got := hex.EncodeToString(sum[:])
	const pinned = "7262cc7867997f8abceb5c421b3c21d742bc171ce8bdb31029b6b616bb3f2911"
	if AttackTermsVersion == "attack-2026-10" && got != pinned {
		t.Fatalf("attack terms changed but version is still %s (sha256 %s)", AttackTermsVersion, got)
	}
	if !strings.Contains(AttackTerms, "version "+AttackTermsVersion) {
		t.Error("the terms text does not name its own version")
	}
	t.Logf("sha256 %s", got)
}

func TestAttackConsentIsSeparateFromScanConsent(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "salt")
	if st, _ := LoadAttackConsent(sp); st != ConsentNone {
		t.Fatal("consent present before accepting")
	}
	if err := RecordConsent(sp, "2026-10-26T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if st, _ := LoadAttackConsent(sp); st != ConsentNone {
		t.Error("accepting the scan terms granted attack-evidence consent")
	}
	if err := RecordAttackConsent(sp, "2026-10-26T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if st, _ := LoadAttackConsent(sp); st != ConsentGranted {
		t.Error("not granted after accepting")
	}
	if err := WithdrawAttackConsent(sp); err != nil {
		t.Fatal(err)
	}
	if st, _ := LoadConsent(sp); st != ConsentGranted {
		t.Error("withdrawing attack consent withdrew the scan consent")
	}
}
