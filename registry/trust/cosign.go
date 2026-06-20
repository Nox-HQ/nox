package trust

import (
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strconv"
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
		// nox publishes plugin signatures as Sigstore v0.3 bundles
		// (GoReleaser/cosign sign-blob --bundle). Verifying them requires
		// `--new-bundle-format`, a flag added in cosign v2.4.0. Older
		// cosign reads the bundle as the legacy Rekor-bundle format and
		// fails with opaque errors ("bundle does not contain cert",
		// "invalid signature when validating ASN.1 encoded signature").
		// Detect that case and return an actionable error instead so an
		// operator with a stale cosign on PATH isn't left guessing.
		if majVal, minVal, ok := cosignVersion(ctx); ok && !supportsNewBundleFormat(majVal, minVal) {
			return fmt.Errorf(
				"cosign v%d.%d is too old to verify Sigstore bundles: nox requires cosign >= v2.4.0 (which added --new-bundle-format). Upgrade cosign (brew upgrade cosign, or sigstore/cosign-installer)",
				majVal, minVal)
		}
		// New bundle format — required by cosign v4, supported by v2.4.0+.
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

// cosignVersionRe extracts the GitVersion line from `cosign version`
// output, e.g. "GitVersion:    v3.0.6" -> major 3, minor 0.
var cosignVersionRe = regexp.MustCompile(`(?m)^GitVersion:\s*v?(\d+)\.(\d+)`)

// cosignVersion shells out to `cosign version` and parses the major and
// minor numbers. ok is false when cosign isn't on PATH, the command
// fails, or the version can't be parsed — callers must treat !ok as
// "unknown" and proceed (never block verification on a parse miss).
func cosignVersion(ctx context.Context) (major, minor int, ok bool) {
	if ctx == nil {
		ctx = context.Background()
	}
	vctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()

	out, err := exec.CommandContext(vctx, "cosign", "version").CombinedOutput()
	if err != nil {
		return 0, 0, false
	}
	m := cosignVersionRe.FindStringSubmatch(string(out))
	if len(m) != 3 {
		return 0, 0, false
	}
	majVal, err := strconv.Atoi(m[1])
	if err != nil {
		return 0, 0, false
	}
	minVal, err := strconv.Atoi(m[2])
	if err != nil {
		return 0, 0, false
	}
	return majVal, minVal, true
}

// supportsNewBundleFormat reports whether a cosign version understands
// the `--new-bundle-format` flag (added in v2.4.0). nox signs and
// publishes Sigstore v0.3 bundles, so verification needs this flag.
func supportsNewBundleFormat(major, minor int) bool {
	if major > 2 {
		return true
	}
	return major == 2 && minor >= 4
}
