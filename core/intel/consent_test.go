package intel

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
	"testing"

	"github.com/nox-hq/nox/core/findings"
)

// The terms are user-facing text a person agreed to. Editing them without
// bumping TermsVersion would bind someone to words they never saw, so the text
// is pinned to its version: change the text, change TermsVersion, update this.
func TestTermsVersionPinsTheText(t *testing.T) {
	const pinned = "bb0d3024ddd4af5bbe76ec55c749455fcff1be168c33c53a9fb99d6a000d8b42"
	sum := sha256.Sum256([]byte(Terms))
	got := hex.EncodeToString(sum[:])
	if TermsVersion == "2026-10" && got != pinned {
		t.Fatalf("Terms text changed but TermsVersion is still %s (sha256 %s). Bump TermsVersion, and the service's NOXINTEL_CONSENT_TERMS, then update this pin.", TermsVersion, got)
	}
	if !strings.Contains(Terms, "version "+TermsVersion) {
		t.Error("the terms text does not name its own version")
	}
}

func TestDeletionKey_DistinctFromIdAndNeverDerivedFromIt(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "salt")
	id, err := ReporterID(sp)
	if err != nil {
		t.Fatal(err)
	}
	key, err := DeletionKey(sp)
	if err != nil {
		t.Fatal(err)
	}
	if key == id || DeletionVerifier(key) == id {
		t.Error("the deletion key or verifier equals the reporter id")
	}
	if k2, _ := DeletionKey(sp); k2 != key {
		t.Error("the deletion key is not stable across calls")
	}
	sum := sha256.Sum256([]byte(key))
	if DeletionVerifier(key) != hex.EncodeToString(sum[:]) {
		t.Error("verifier is not hex(sha256(key))")
	}
	ex, found, err := ExistingIdentity(sp)
	if err != nil || !found || ex.ReporterID != id || ex.DeletionKey != key {
		t.Errorf("ExistingIdentity disagrees with the creating derivations: %+v %v %v", ex, found, err)
	}
}

func TestExistingIdentity_CreatesNothing(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "sub", "salt")
	_, found, err := ExistingIdentity(sp)
	if err != nil || found {
		t.Fatalf("found=%v err=%v for a missing salt", found, err)
	}
	if _, err := os.Stat(filepath.Dir(sp)); !os.IsNotExist(err) {
		t.Error("looking up an identity created files")
	}
}

func TestConsent_LifecycleAndVersioning(t *testing.T) {
	sp := filepath.Join(t.TempDir(), "salt")
	if s, _ := LoadConsent(sp); s != ConsentNone {
		t.Fatalf("fresh install status = %v", s)
	}
	if err := RecordConsent(sp, "2026-10-25T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	if s, c := LoadConsent(sp); s != ConsentGranted || c.TermsVersion != TermsVersion {
		t.Fatalf("after accept: %v %+v", s, c)
	}
	fi, err := os.Stat(ConsentPath(sp))
	if err != nil || fi.Mode().Perm() != 0o600 {
		t.Errorf("consent file mode: %v %v", fi, err)
	}
	if err := os.WriteFile(ConsentPath(sp), []byte(`{"terms_version":"2024-01"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, _ := LoadConsent(sp); s != ConsentStale {
		t.Errorf("older terms status = %v, want stale", s)
	}
	if err := os.WriteFile(ConsentPath(sp), []byte(`not json`), 0o600); err != nil {
		t.Fatal(err)
	}
	if s, _ := LoadConsent(sp); s != ConsentNone {
		t.Errorf("garbage status = %v, want none", s)
	}
	if err := WithdrawConsent(sp); err != nil {
		t.Fatal(err)
	}
	if err := WithdrawConsent(sp); err != nil {
		t.Errorf("withdrawing twice: %v", err)
	}
}

// v2Double refuses what the real intake refuses: a body that is not schema 2
// with a consent version.
func v2Double(t *testing.T, seen *[]map[string]any) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		var m map[string]any
		_ = json.Unmarshal(b, &m)
		*seen = append(*seen, m)
		if m["schema_version"] != float64(2) || m["consent_version"] == "" || m["consent_version"] == nil {
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":"consent required","code":"consent_required"}`))
			return
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func TestDerive_ProducesSchema2Body(t *testing.T) {
	obs := Derive([]findings.Finding{depFinding("lodash", "npm", "4.17.15", "4.17.21")}, DeriveOptions{
		ReporterID: "r", ObservedAt: "2026-10-25T00:00:00Z", ConsentVersion: TermsVersion, DeletionVerifier: "v",
	})
	if len(obs) == 0 {
		t.Fatal("no observations")
	}
	var seen []map[string]any
	srv := v2Double(t, &seen)
	res := NewClient(srv.URL, nil).Contribute(context.Background(), obs)
	if res.Accepted != len(obs) || res.FirstError != nil {
		t.Fatalf("v2 double refused a well-formed body: %+v", res)
	}
	if seen[0]["schema_version"] != float64(2) || seen[0]["consent_version"] != TermsVersion || seen[0]["deletion_verifier"] != "v" {
		t.Errorf("body = %v", seen[0])
	}
}

func TestContribute_NeverSendsWithoutConsentVersion(t *testing.T) {
	obs := Derive([]findings.Finding{depFinding("lodash", "npm", "4.17.15", "4.17.21")}, DeriveOptions{ReporterID: "r", ObservedAt: "x"})
	var seen []map[string]any
	srv := v2Double(t, &seen)
	res := NewClient(srv.URL, nil).Contribute(context.Background(), obs)
	if len(seen) != 0 || res.Accepted != 0 || res.FirstError == nil {
		t.Fatalf("an observation without consent_version reached the wire: seen=%d res=%+v", len(seen), res)
	}
}

func TestErase_Contract(t *testing.T) {
	var got map[string]string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost || r.URL.Path != "/v1/reporters/erase" {
			w.WriteHeader(404)
			return
		}
		_ = json.NewDecoder(r.Body).Decode(&got)
		if got["deletion_key"] != "k" {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":"this reporter bound a deletion key","code":"erasure_proof_invalid"}`))
			return
		}
		_, _ = w.Write([]byte(`{"candidates_anonymised":3,"identifiers_removed":4,"consent_removed":true,"proof":"deletion_key"}`))
	}))
	defer srv.Close()
	c := NewClient(srv.URL, nil)

	res, err := c.Erase(context.Background(), "rid", "k")
	if err != nil || res.CandidatesAnonymised != 3 || res.IdentifiersRemoved != 4 || !res.ConsentRemoved || res.Proof != "deletion_key" {
		t.Fatalf("res=%+v err=%v", res, err)
	}
	if got["reporter_id"] != "rid" {
		t.Errorf("body = %v", got)
	}
	if _, err := c.Erase(context.Background(), "rid", "wrong"); err == nil || !strings.Contains(err.Error(), "bound a deletion key") {
		t.Errorf("a 403 must be an error carrying the reason: %v", err)
	}
}
