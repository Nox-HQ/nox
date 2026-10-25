package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/nox-hq/nox/core/intel"
)

func contributor(t *testing.T) (salt string) {
	t.Helper()
	salt = filepath.Join(t.TempDir(), "salt")
	if _, err := intel.ReporterID(salt); err != nil {
		t.Fatal(err)
	}
	if err := intel.RecordConsent(salt, "2026-10-25T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	return salt
}

func TestForget_ErasesReportsCountsAndWithdrawsConsent(t *testing.T) {
	salt := contributor(t)
	id, _, _ := intel.ExistingIdentity(salt)
	var body strings.Builder
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b := make([]byte, 4096)
		n, _ := r.Body.Read(b)
		body.Write(b[:n])
		_, _ = w.Write([]byte(`{"candidates_anonymised":2,"identifiers_removed":5,"consent_removed":true,"proof":"deletion_key"}`))
	}))
	defer srv.Close()

	var out, errw bytes.Buffer
	if code := intelForget([]string{"--endpoint", srv.URL, "--salt-path", salt}, &out, &errw); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	if !strings.Contains(body.String(), id.ReporterID) || !strings.Contains(body.String(), id.DeletionKey) {
		t.Errorf("request lacked id or key: %s", body.String())
	}
	if !strings.Contains(out.String(), "2 report(s)") || !strings.Contains(out.String(), "5 identifier(s)") {
		t.Errorf("counts not reported: %s", out.String())
	}
	if s, _ := intel.LoadConsent(salt); s != intel.ConsentNone {
		t.Error("consent not withdrawn after confirmed erasure")
	}
}

// Failure changes nothing locally: a local "forgotten" state with the data
// still on the service would be a false all-clear.
func TestForget_FailureChangesNothingLocally(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"refused": func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(403)
			_, _ = w.Write([]byte(`{"error":"nope"}`))
		},
		"server down": func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) },
	} {
		t.Run(name, func(t *testing.T) {
			salt := contributor(t)
			srv := httptest.NewServer(handler)
			defer srv.Close()
			var out, errw bytes.Buffer
			if code := intelForget([]string{"--endpoint", srv.URL, "--salt-path", salt}, &out, &errw); code == 0 {
				t.Fatal("a failed erasure exited 0")
			}
			if s, _ := intel.LoadConsent(salt); s != intel.ConsentGranted {
				t.Error("consent was changed although erasure failed")
			}
			if !strings.Contains(errw.String(), "Nothing was changed") {
				t.Errorf("failure not stated plainly: %s", errw.String())
			}
		})
	}
}

func TestForget_Unreachable(t *testing.T) {
	salt := contributor(t)
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL
	srv.Close()
	var out, errw bytes.Buffer
	if code := intelForget([]string{"--endpoint", url, "--salt-path", salt}, &out, &errw); code == 0 {
		t.Fatal("unreachable service exited 0")
	}
	if s, _ := intel.LoadConsent(salt); s != intel.ConsentGranted {
		t.Error("consent changed although the service was unreachable")
	}
}

func TestForget_NeverContributedMakesNoRequest(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { hits.Add(1) }))
	defer srv.Close()
	salt := filepath.Join(t.TempDir(), "salt")
	var out, errw bytes.Buffer
	if code := intelForget([]string{"--endpoint", srv.URL, "--salt-path", salt}, &out, &errw); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	if hits.Load() != 0 {
		t.Error("a request was made for an installation with no identity")
	}
	if _, err := os.Stat(salt); !os.IsNotExist(err) {
		t.Error("forget minted a salt")
	}
}

func TestConsent_AcceptRequiresExplicitYesOrNamedVersion(t *testing.T) {
	salt := filepath.Join(t.TempDir(), "salt")
	var out, errw bytes.Buffer

	if code := intelConsent([]string{"accept", "--salt-path", salt}, strings.NewReader("\n"), &out, &errw); code == 0 {
		t.Error("an empty answer was taken as acceptance")
	}
	if s, _ := intel.LoadConsent(salt); s != intel.ConsentNone {
		t.Error("consent recorded without an answer")
	}
	if code := intelConsent([]string{"accept", "--accept-terms", "2024-01", "--salt-path", salt}, nil, &out, &errw); code == 0 {
		t.Error("an outdated version was accepted")
	}
	if !strings.Contains(out.String(), "version "+intel.TermsVersion) {
		t.Error("the terms were not shown before asking")
	}
	if code := intelConsent([]string{"accept", "--salt-path", salt}, strings.NewReader("yes\n"), &out, &errw); code != 0 {
		t.Fatalf("yes: exit %d %s", code, errw.String())
	}
	if s, _ := intel.LoadConsent(salt); s != intel.ConsentGranted {
		t.Error("yes did not record consent")
	}
	_ = intelConsent([]string{"withdraw", "--salt-path", salt}, nil, &out, &errw)
	if code := intelConsent([]string{"accept", "--accept-terms", intel.TermsVersion, "--salt-path", salt}, nil, &out, &errw); code != 0 {
		t.Fatalf("named version: exit %d", code)
	}
	if s, _ := intel.LoadConsent(salt); s != intel.ConsentGranted {
		t.Error("named version did not record consent")
	}
}

// Erasure unlinks the old id on the service; if the same salt were kept, the
// next consent would mint the same id and silently re-link the installation.
// After a confirmed forget a later contribution must be a new reporter.
func TestForget_RotatesTheSaltSoReconsentIsANewReporter(t *testing.T) {
	salt := contributor(t)
	before, _, _ := intel.ExistingIdentity(salt)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"candidates_anonymised":1,"identifiers_removed":1,"consent_removed":true,"proof":"deletion_key"}`))
	}))
	defer srv.Close()
	var out, errw bytes.Buffer
	if code := intelForget([]string{"--endpoint", srv.URL, "--salt-path", salt}, &out, &errw); code != 0 {
		t.Fatalf("exit %d: %s", code, errw.String())
	}
	if _, found, _ := intel.ExistingIdentity(salt); found {
		t.Error("the old reporter salt survived a confirmed erasure")
	}
	// Re-consent, as a later `nox intel consent` and scan would.
	if err := intel.RecordConsent(salt, "2027-01-01T00:00:00Z"); err != nil {
		t.Fatal(err)
	}
	again, err := intel.ReporterID(salt)
	if err != nil {
		t.Fatal(err)
	}
	if again == before.ReporterID {
		t.Error("re-consent reused the erased reporter id: the two periods are linkable")
	}
	if !strings.Contains(out.String(), "new, unlinkable reporter") {
		t.Errorf("the operator is not told: %s", out.String())
	}
}

// A failed erasure keeps the salt: it is the only credential that can retry.
func TestForget_FailureKeepsTheSalt(t *testing.T) {
	salt := contributor(t)
	before, _, _ := intel.ExistingIdentity(salt)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(503) }))
	defer srv.Close()
	var out, errw bytes.Buffer
	if code := intelForget([]string{"--endpoint", srv.URL, "--salt-path", salt}, &out, &errw); code == 0 {
		t.Fatal("exit 0")
	}
	after, found, _ := intel.ExistingIdentity(salt)
	if !found || after != before {
		t.Error("the salt changed although the service did not confirm erasure")
	}
}
