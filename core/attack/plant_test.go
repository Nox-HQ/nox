package attack

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPlantWritesAndCleansUp(t *testing.T) {
	dir := t.TempDir()
	cs := MintCanaries("plant-seed")

	planted, cleanup, err := Plant(cs, dir, ProfileSandbox, true)
	if err != nil {
		t.Fatalf("Plant: %v", err)
	}
	if len(planted) != 1 {
		t.Fatalf("planted %d canary(ies), want 1", len(planted))
	}

	path := planted[0].Path
	if filepath.Base(path) != ExfilFileName() {
		t.Errorf("planted at %s, want the file name the payload asks for (%s)", path, ExfilFileName())
	}
	body, err := os.ReadFile(path) //nolint:gosec // path is the temp dir we just wrote
	if err != nil {
		t.Fatalf("reading planted canary: %v", err)
	}
	if !strings.Contains(string(body), planted[0].Canary.Value) {
		t.Error("planted file does not contain the canary value; the oracle could never fire")
	}
	// The file must announce itself. An operator finding it later has to be
	// able to tell it is nox's and not a real leaked credential.
	if !strings.Contains(string(body), "nox") || !strings.Contains(string(body), "Not a real credential") {
		t.Errorf("planted file must identify itself as a nox canary, got:\n%s", body)
	}

	if err := cleanup(); err != nil {
		t.Fatalf("cleanup: %v", err)
	}
	if _, err := os.Stat(path); !errors.Is(err, os.ErrNotExist) {
		t.Error("cleanup left the canary behind; a fake secret must not outlive the run")
	}
	// Cleanup is deferred by callers and may run twice on an error path.
	if err := cleanup(); err != nil {
		t.Errorf("cleanup must be idempotent, second call returned %v", err)
	}
}

// The canary value must never appear in a payload, planted or not — otherwise
// an echoing target could reproduce it and fake a confirmation.
func TestPlantedCanaryStaysReflectionImmune(t *testing.T) {
	cs := MintCanaries("plant-seed")
	if err := cs.AssertReflectionImmune(PayloadCorpus(cs)); err != nil {
		t.Fatalf("corpus is not reflection-immune: %v", err)
	}
	for _, p := range PayloadCorpus(cs) {
		if strings.Contains(p, cs.file.Value) {
			t.Fatalf("a payload carries the file canary value; an echo could fake an exfiltration")
		}
	}
}

func TestPlantRefusals(t *testing.T) {
	cs := MintCanaries("plant-seed")
	existing := t.TempDir()
	occupied := filepath.Join(existing, ExfilFileName())
	if err := os.WriteFile(occupied, []byte("the operator's real file\n"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}

	tests := []struct {
		name       string
		dir        string
		profile    Profile
		authorized bool
		wantErr    error
		wantSubstr string
	}{
		{
			name:       "safe profile sends nothing, so planting would be a pointless write",
			dir:        t.TempDir(),
			profile:    ProfileSafe,
			authorized: true,
			wantSubstr: "sends no traffic",
		},
		{
			name:       "unauthorized",
			dir:        t.TempDir(),
			profile:    ProfileSandbox,
			authorized: false,
			wantErr:    ErrPlantNotAuthorized,
		},
		{
			name:       "no directory given",
			dir:        "",
			profile:    ProfileSandbox,
			authorized: true,
			wantSubstr: "never guesses",
		},
		{
			name:       "directory does not exist and is NOT created",
			dir:        filepath.Join(t.TempDir(), "does", "not", "exist"),
			profile:    ProfileSandbox,
			authorized: true,
			wantSubstr: "must already exist",
		},
		{
			name:       "refuses to overwrite the operator's file",
			dir:        existing,
			profile:    ProfileSandbox,
			authorized: true,
			wantErr:    ErrPlantTargetExists,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, cleanup, err := Plant(cs, tt.dir, tt.profile, tt.authorized)
			if err == nil {
				t.Fatal("expected a refusal")
			}
			if tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
				t.Errorf("error = %v, want %v", err, tt.wantErr)
			}
			if tt.wantSubstr != "" && !strings.Contains(err.Error(), tt.wantSubstr) {
				t.Errorf("error %q should mention %q", err, tt.wantSubstr)
			}
			// A refused plant must still return a usable cleanup, because
			// callers defer it before checking the error.
			if cleanup == nil {
				t.Fatal("cleanup must never be nil, callers defer it unconditionally")
			}
			if err := cleanup(); err != nil {
				t.Errorf("cleanup after a refusal returned %v, want nil", err)
			}
		})
	}

	// The operator's file must be exactly as they left it.
	body, err := os.ReadFile(occupied) //nolint:gosec // fixture path
	if err != nil {
		t.Fatalf("reading the operator's file: %v", err)
	}
	if string(body) != "the operator's real file\n" {
		t.Fatalf("nox modified a file it did not create: %q", body)
	}
}

func TestPlantRejectsANonDirectory(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "a-file")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	if _, _, err := Plant(MintCanaries("s"), file, ProfileSandbox, true); err == nil {
		t.Fatal("expected a refusal when the plant path is not a directory")
	}
}

func TestPlantNilCanarySet(t *testing.T) {
	if _, _, err := Plant(nil, t.TempDir(), ProfileSandbox, true); err == nil {
		t.Fatal("expected an error for a nil canary set")
	}
}
