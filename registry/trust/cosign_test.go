package trust

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestCosignVerifyBlob_NoBinary(t *testing.T) {
	// Empty PATH so cosign isn't found.
	t.Setenv("PATH", t.TempDir())

	err := CosignVerifyBlob(context.Background(), CosignVerifyParams{
		ArtifactPath:              "/tmp/whatever",
		SignaturePath:             "/tmp/whatever.sig",
		CertificateIdentityRegexp: "https://github.com/.*/.github/workflows/release.yml@.*",
	})
	if !errors.Is(err, ErrCosignNotInstalled) {
		t.Fatalf("expected ErrCosignNotInstalled, got %v", err)
	}
}

func TestCosignVerifyBlob_RequiresPaths(t *testing.T) {
	if _, err := exec.LookPath("cosign"); err != nil {
		t.Skip("cosign not installed; not testing real verify")
	}
	err := CosignVerifyBlob(context.Background(), CosignVerifyParams{
		CertificateIdentityRegexp: "https://example.com/.*",
	})
	if err == nil || !strings.Contains(err.Error(), "required") {
		t.Errorf("expected required-path error, got %v", err)
	}
}

func TestCosignAvailable_HonoursPath(t *testing.T) {
	t.Setenv("PATH", t.TempDir())
	if CosignAvailable() {
		t.Error("expected cosign unavailable with empty PATH")
	}
}

func TestSupportsNewBundleFormat(t *testing.T) {
	tests := []struct {
		major, minor int
		want         bool
	}{
		{1, 13, false}, // legacy cosign v1
		{2, 0, false},  // v2.0 — before --new-bundle-format
		{2, 3, false},  // v2.3 — still before
		{2, 4, true},   // v2.4.0 introduced --new-bundle-format
		{2, 6, true},
		{3, 0, true}, // cosign v3 (what cosign-installer v4.1.2 installs)
		{3, 1, true},
		{4, 0, true}, // future cosign v4
	}
	for _, tt := range tests {
		if got := supportsNewBundleFormat(tt.major, tt.minor); got != tt.want {
			t.Errorf("supportsNewBundleFormat(%d,%d) = %v, want %v", tt.major, tt.minor, got, tt.want)
		}
	}
}

// fakeCosignVersion installs a stub `cosign` on PATH whose `version`
// subcommand prints the given GitVersion line.
func fakeCosignVersion(t *testing.T, gitVersion string) {
	t.Helper()
	dir := t.TempDir()
	script := "#!/bin/sh\n" +
		"if [ \"$1\" = version ]; then\n" +
		"  echo 'GitVersion:    " + gitVersion + "'\n" +
		"  exit 0\n" +
		"fi\n" +
		"exit 0\n"
	if err := os.WriteFile(filepath.Join(dir, "cosign"), []byte(script), 0o755); err != nil {
		t.Fatalf("writing fake cosign: %v", err)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
}

func TestCosignVersion_Parses(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake cosign shim uses a POSIX shell script")
	}
	fakeCosignVersion(t, "v3.0.6")
	majVal, minVal, ok := cosignVersion(context.Background())
	if !ok {
		t.Fatal("expected version parse to succeed")
	}
	if majVal != 3 || minVal != 0 {
		t.Errorf("cosignVersion = v%d.%d, want v3.0", majVal, minVal)
	}
}

func TestCosignVerifyBlob_RejectsOldCosignForBundle(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("fake cosign shim uses a POSIX shell script")
	}
	fakeCosignVersion(t, "v2.2.4") // pre --new-bundle-format
	err := CosignVerifyBlob(context.Background(), CosignVerifyParams{
		ArtifactPath:              filepath.Join(t.TempDir(), "checksums.txt"),
		BundlePath:                filepath.Join(t.TempDir(), "checksums.txt.sigstore.json"),
		CertificateIdentityRegexp: "https://github.com/x/y/.github/workflows/release.yml@.*",
	})
	if err == nil || !strings.Contains(err.Error(), "too old") {
		t.Fatalf("expected too-old cosign error, got %v", err)
	}
}
