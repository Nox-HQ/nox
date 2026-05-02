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
	// cosign sign-blob (legacy format, cosign v3.x).
	SignaturePath string
	// BundlePath is the local path to the .sig.bundle file produced
	// by cosign sign-blob --new-bundle-format. Required for cosign v4
	// verification. When set, takes precedence over SignaturePath.
	BundlePath string
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
	if p.ArtifactPath == "" {
		return fmt.Errorf("cosign verify-blob: artifact path required")
	}
	if p.BundlePath == "" && p.SignaturePath == "" {
		return fmt.Errorf("cosign verify-blob: bundle or signature path required")
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

	args := []string{
		"verify-blob",
		"--certificate-identity-regexp", p.CertificateIdentityRegexp,
		"--certificate-oidc-issuer", issuer,
	}
	if p.BundlePath != "" {
		// New bundle format — required by cosign v4, supported by v3.10+.
		args = append(args, "--bundle", p.BundlePath, "--new-bundle-format")
	} else {
		// Legacy --signature path. Cosign v4 rejects this; falls
		// through to a clearer error message.
		args = append(args, "--signature", p.SignaturePath)
	}
	args = append(args, p.ArtifactPath)

	cmd := exec.CommandContext(ctx, "cosign", args...)
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
