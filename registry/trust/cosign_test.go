package trust

import (
	"context"
	"errors"
	"os/exec"
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
