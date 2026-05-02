package trust

import (
	"context"
	"fmt"
	"os/exec"
	"strings"
	"time"
)

// CosignVerifyParams describes the keyless verification an operator
// (or the install path) wants run against a release artifact.
//
// nox doesn't ship a Sigstore SDK in core — that would balloon the
// binary. Instead, when `cosign` is on the operator's PATH, the
// verifier shells out to `cosign verify-blob`. When it's not on
// PATH, the call returns ErrCosignNotInstalled and the caller falls
// through to Ed25519 verification only.
type CosignVerifyParams struct {
	// ArtifactPath is the local path to the artifact bytes. The
	// caller must have already downloaded the artifact to disk.
	ArtifactPath string
	// SignaturePath is the local path to the .sig file produced by
	// cosign sign-blob.
	SignaturePath string
	// CertificateIdentityRegexp matches the OIDC subject expected on
	// the signing certificate. For GitHub Actions release pipelines
	// this looks like:
	//   https://github.com/<owner>/<repo>/.github/workflows/release.yml@.*
	CertificateIdentityRegexp string
	// CertificateOIDCIssuer is the OIDC issuer URL. For GitHub:
	//   https://token.actions.githubusercontent.com
	CertificateOIDCIssuer string
}

// ErrCosignNotInstalled is returned when the cosign binary isn't on
// PATH. Callers fall through to Ed25519 verification rather than
// failing the install.
var ErrCosignNotInstalled = fmt.Errorf("cosign binary not found on PATH; install with: brew install cosign or go install github.com/sigstore/cosign/v2/cmd/cosign@latest")

// CosignVerifyBlob shells out to `cosign verify-blob` with the
// supplied parameters. Returns nil on a verified signature, an error
// describing the violation otherwise.
//
// The function deliberately accepts a context so callers can bound
// the verification time — Sigstore network calls (Rekor lookup, OIDC
// trust root fetch) can hang under transient failure modes.
func CosignVerifyBlob(ctx context.Context, p CosignVerifyParams) error {
	if _, err := exec.LookPath("cosign"); err != nil {
		return ErrCosignNotInstalled
	}
	if p.ArtifactPath == "" || p.SignaturePath == "" {
		return fmt.Errorf("cosign verify-blob: artifact and signature paths are required")
	}
	if p.CertificateIdentityRegexp == "" {
		return fmt.Errorf("cosign verify-blob: certificate-identity-regexp is required")
	}
	issuer := p.CertificateOIDCIssuer
	if issuer == "" {
		issuer = "https://token.actions.githubusercontent.com"
	}

	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx,
		"cosign", "verify-blob",
		"--certificate-identity-regexp", p.CertificateIdentityRegexp,
		"--certificate-oidc-issuer", issuer,
		"--signature", p.SignaturePath,
		p.ArtifactPath,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("cosign verify-blob failed: %w\n%s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CosignAvailable reports whether the cosign binary is installed.
// Callers use this to decide whether to attempt keyless verification
// or skip straight to Ed25519.
func CosignAvailable() bool {
	_, err := exec.LookPath("cosign")
	return err == nil
}
