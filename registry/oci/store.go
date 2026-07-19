// Package oci provides content-addressed artifact storage for Nox plugins.
// It downloads plugin binaries, verifies digests via the trust layer, and
// stores them in a sharded local cache.
package oci

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/registry/trust"
)

const (
	defaultMaxDownloadSize = 500 * 1024 * 1024 // 500 MB
	defaultDownloadTimeout = 5 * time.Minute
)

// ErrDigestMismatch indicates the downloaded artifact digest does not match expected.
var ErrDigestMismatch = errors.New("downloaded artifact digest does not match expected")

// InstalledArtifact describes a fetched and verified artifact in the local cache.
type InstalledArtifact struct {
	PluginName   string
	Version      string
	OS           string
	Arch         string
	Digest       string
	BlobPath     string // content-addressed blob path
	ExtractDir   string // extracted directory (empty for raw binary)
	BinaryPath   string // path to the executable
	Format       ArtifactFormat
	Size         int64
	VerifyResult trust.VerifyResult
}

// Store manages a content-addressed cache of plugin artifacts.
type Store struct {
	cacheDir   string
	httpClient *http.Client
	verifier   *trust.Verifier
	maxSize    int64
	mirrorBase string
}

// StoreOption is a functional option for configuring a Store.
type StoreOption func(*Store)

// WithCacheDir sets the directory for artifact storage.
func WithCacheDir(dir string) StoreOption {
	return func(s *Store) { s.cacheDir = dir }
}

// WithHTTPClient sets a custom HTTP client for downloads.
func WithHTTPClient(hc *http.Client) StoreOption {
	return func(s *Store) { s.httpClient = hc }
}

// WithVerifier sets the trust verifier for artifact verification.
func WithVerifier(v *trust.Verifier) StoreOption {
	return func(s *Store) { s.verifier = v }
}

// WithMaxDownloadSize sets the maximum allowed download size in bytes.
func WithMaxDownloadSize(n int64) StoreOption {
	return func(s *Store) { s.maxSize = n }
}

// WithMirrorBase sets the mirror base URL for air-gapped environments.
// Downloads will have their scheme+host replaced with the mirror base.
func WithMirrorBase(base string) StoreOption {
	return func(s *Store) { s.mirrorBase = base }
}

// NewStore creates a Store with the given options.
func NewStore(opts ...StoreOption) *Store {
	s := &Store{
		cacheDir:   filepath.Join(os.Getenv("HOME"), ".nox", "cache", "artifacts"),
		httpClient: &http.Client{Timeout: defaultDownloadTimeout},
		verifier:   trust.NewVerifier(),
		maxSize:    defaultMaxDownloadSize,
	}
	for _, opt := range opts {
		opt(s)
	}
	return s
}

// Fetch downloads, verifies, caches, and extracts a plugin artifact.
// If the artifact is already cached, the download is skipped.
func (s *Store) Fetch(ctx context.Context, name string, ve *registry.VersionEntry) (*InstalledArtifact, error) {
	// 1. Select platform-appropriate artifact.
	artifact, err := SelectArtifact(ve.Artifacts)
	if err != nil {
		return nil, fmt.Errorf("selecting artifact for %s: %w", name, err)
	}

	return s.fetchArtifact(ctx, name, ve, artifact)
}

// FetchFor downloads an artifact for a specific OS/arch combination.
func (s *Store) FetchFor(ctx context.Context, name string, ve *registry.VersionEntry, goos, goarch string) (*InstalledArtifact, error) {
	artifact, err := SelectArtifactFor(ve.Artifacts, goos, goarch)
	if err != nil {
		return nil, fmt.Errorf("selecting artifact for %s (%s/%s): %w", name, goos, goarch, err)
	}

	return s.fetchArtifact(ctx, name, ve, artifact)
}

func (s *Store) fetchArtifact(ctx context.Context, name string, ve *registry.VersionEntry, artifact *registry.PlatformArtifact) (*InstalledArtifact, error) {
	// Refuse to install when the registry entry hasn't been stamped
	// with a real digest. A placeholder ("sha256:tbd") or empty value
	// means the publisher hasn't completed the release pipeline; trust
	// is impossible because the bytes that arrive aren't bound to a
	// known hash. Marketplace authoring tooling stamps "sha256:tbd"
	// before binaries land — this gate ensures operators never install
	// against an unfinished entry.
	if !isRealDigest(artifact.Digest) {
		return nil, fmt.Errorf(
			"refusing to install %s@%s: artifact digest %q is a placeholder or missing. The plugin's release pipeline must stamp the real SHA-256 in the registry index (github.com/nox-hq/registry) before installs can proceed",
			name, ve.Version, artifact.Digest)
	}

	blobPath := s.BlobPath(artifact.Digest)

	// 2. Check cache.
	if !s.Has(artifact.Digest) {
		// 3. Download.
		tmpPath, _, err := s.download(ctx, artifact.URL, artifact.Size)
		if err != nil {
			return nil, fmt.Errorf("downloading %s: %w", name, err)
		}
		defer func() {
			// Clean up temp file if it still exists (e.g. on error before rename).
			_ = os.Remove(tmpPath)
		}()

		// 4. Verify digest.
		data, err := os.ReadFile(tmpPath)
		if err != nil {
			return nil, fmt.Errorf("reading downloaded artifact: %w", err)
		}

		match, err := trust.VerifyDigest(data, artifact.Digest)
		if err != nil {
			return nil, fmt.Errorf("verifying digest: %w", err)
		}
		if !match {
			return nil, ErrDigestMismatch
		}

		// 5. Atomic rename to content-addressed path.
		shardDir := filepath.Dir(blobPath)
		if err := os.MkdirAll(shardDir, 0o755); err != nil {
			return nil, fmt.Errorf("creating shard dir: %w", err)
		}
		if err := os.Rename(tmpPath, blobPath); err != nil {
			return nil, fmt.Errorf("storing blob: %w", err)
		}
	}

	// 6. Trust verification (always run, even on cache hit, for result reporting).
	blobData, err := os.ReadFile(blobPath)
	if err != nil {
		return nil, fmt.Errorf("reading cached blob: %w", err)
	}

	verifyResult := s.verifier.VerifyArtifact(
		blobData,
		artifact.Digest,
		ve.Signature,
		ve.SignerKeyPEM,
		ve.APIVersion,
	)

	// Optional cosign keyless verification. The cosign signature is
	// produced by GoReleaser over the release's `checksums.txt`, NOT
	// over the per-platform tarball directly. Trust chain:
	//
	//   cosign(checksums.txt) signed by release.yml workflow OIDC
	//      ⇒ checksums.txt contains <hex>  <tarball-name>
	//      ⇒ tarball SHA-256 == registry artifact.Digest (verified above)
	//
	// We therefore fetch checksums.txt, run cosign verify-blob against
	// it, then confirm the artifact's filename is listed in the file
	// with the same digest the registry advertised. Either step
	// failing yields a violation; cosign-not-installed is silent.
	if (artifact.CosignSigURL != "" || artifact.CosignBundleURL != "") && trust.CosignAvailable() {
		checksumsURL := deriveChecksumsURL(artifact.CosignBundleURL, artifact.CosignSigURL)
		checksumsPath, fetchErr := s.downloadChecksums(ctx, checksumsURL)
		if fetchErr != nil {
			verifyResult.Violations = append(verifyResult.Violations, trust.Violation{
				Field:   "cosign_signature",
				Message: fmt.Sprintf("downloading checksums.txt: %v", fetchErr),
			})
		} else {
			params := trust.CosignVerifyParams{
				ArtifactPath:              checksumsPath,
				CertificateIdentityRegexp: artifact.CosignCertIdentityRegexp,
				CertificateOIDCIssuer:     artifact.CosignOIDCIssuer,
			}
			if artifact.CosignBundleURL != "" {
				params.BundlePath, fetchErr = s.downloadSignature(ctx, artifact.CosignBundleURL)
			} else {
				params.SignaturePath, fetchErr = s.downloadSignature(ctx, artifact.CosignSigURL)
			}
			if fetchErr != nil {
				verifyResult.Violations = append(verifyResult.Violations, trust.Violation{
					Field:   "cosign_signature",
					Message: fmt.Sprintf("downloading signature: %v", fetchErr),
				})
			} else if err := trust.CosignVerifyBlob(ctx, params); err != nil {
				verifyResult.Violations = append(verifyResult.Violations, trust.Violation{
					Field:   "cosign_signature",
					Message: err.Error(),
				})
			} else if mismatch, mErr := verifyChecksumsListsArtifact(checksumsPath, artifact.URL, artifact.Digest); mErr != nil {
				verifyResult.Violations = append(verifyResult.Violations, trust.Violation{
					Field:   "cosign_signature",
					Message: mErr.Error(),
				})
			} else if mismatch {
				verifyResult.Violations = append(verifyResult.Violations, trust.Violation{
					Field:   "cosign_signature",
					Message: "checksums.txt does not list the artifact filename or digest disagrees with registry entry",
				})
			} else {
				// Cosign keyless verification + checksums binding both
				// passed. Promote to TrustCommunity so DefaultPolicy
				// accepts the artifact without an Ed25519 signer key.
				if verifyResult.Level < trust.TrustCommunity {
					verifyResult.Level = trust.TrustCommunity
				}
				verifyResult.SignatureValid = true
				verifyResult.SignerName = "cosign-keyless:" + artifact.CosignCertIdentityRegexp
				// Re-enforce policy after promotion: VerifyArtifact ran
				// Policy.Enforce when level was still TrustUnverified
				// (cosign hadn't been consulted yet) and may have
				// recorded a trust_level violation. Drop those and
				// re-run so the post-promotion level is authoritative.
				verifyResult.Violations = dropPolicyLevelViolations(verifyResult.Violations)
				verifyResult.Violations = append(verifyResult.Violations, s.verifier.Policy().Enforce(&verifyResult)...)
			}
		}
	}

	// 7. Detect format and extract/set executable.
	format, err := DetectFormat(blobPath)
	if err != nil {
		return nil, fmt.Errorf("detecting format: %w", err)
	}

	installed := &InstalledArtifact{
		PluginName:   name,
		Version:      ve.Version,
		OS:           artifact.OS,
		Arch:         artifact.Arch,
		Digest:       artifact.Digest,
		BlobPath:     blobPath,
		Format:       format,
		Size:         int64(len(blobData)),
		VerifyResult: verifyResult,
	}

	switch format {
	case FormatTarGz:
		extractDir := s.extractPath(artifact.Digest)
		if _, err := os.Stat(extractDir); os.IsNotExist(err) {
			if _, err := ExtractTarGz(blobPath, extractDir); err != nil {
				return nil, fmt.Errorf("extracting artifact: %w", err)
			}
		}
		installed.ExtractDir = extractDir
		// Locate the actual executable: the binary is often named after the
		// plugin's repo (e.g. "nox-plugin-taint-analysis"), not its short
		// registry name, so a fixed base-name guess misses it.
		installed.BinaryPath = findPluginBinary(extractDir, name)

	case FormatRawBinary:
		if err := SetExecutable(blobPath); err != nil {
			return nil, fmt.Errorf("setting executable: %w", err)
		}
		installed.BinaryPath = blobPath
	}

	return installed, nil
}

// Has reports whether a blob with the given digest exists in the cache.
func (s *Store) Has(digest string) bool {
	_, err := os.Stat(s.BlobPath(digest))
	return err == nil
}

// BlobPath returns the content-addressed path for a given digest.
// The path is sharded by the first two hex characters: sha256/<ab>/<fullhex>
func (s *Store) BlobPath(digest string) string {
	hex := digestHex(digest)
	if len(hex) < 2 {
		return filepath.Join(s.cacheDir, "sha256", hex)
	}
	return filepath.Join(s.cacheDir, "sha256", hex[:2], hex)
}

// extractPath returns the directory where an extracted artifact lives.
func (s *Store) extractPath(digest string) string {
	hex := digestHex(digest)
	if len(hex) < 2 {
		return filepath.Join(s.cacheDir, "extracted", hex)
	}
	return filepath.Join(s.cacheDir, "extracted", hex[:2], hex)
}

// digestHex strips the "sha256:" prefix from a digest string.
func digestHex(digest string) string {
	const prefix = "sha256:"
	if len(digest) > len(prefix) && digest[:len(prefix)] == prefix {
		return digest[len(prefix):]
	}
	return digest
}

// dropPolicyLevelViolations removes the `trust_level` violation
// (added by Policy.Enforce when level < MinLevel) from a slice. The
// install path uses this to discard a stale violation after an
// out-of-band cosign verification promotes the result's Level.
func dropPolicyLevelViolations(in []trust.Violation) []trust.Violation {
	if len(in) == 0 {
		return in
	}
	out := in[:0]
	for _, v := range in {
		if v.Field == "trust_level" {
			continue
		}
		out = append(out, v)
	}
	return out
}

// deriveChecksumsURL strips the GoReleaser signing suffix from a
// cosign signature URL to recover the URL of the checksums.txt that
// was signed. Both `.sig.bundle` (cosign v4) and `.sig` (cosign v3.x)
// resolve to the same `checksums.txt`.
func deriveChecksumsURL(bundleURL, sigURL string) string {
	if bundleURL != "" {
		// The bundle is named "<checksums>.<suffix>". cosign v3.10+/v4 emit
		// ".sigstore.json"; older releases emit ".sig.bundle". Strip whichever
		// is present so the real checksums file is fetched as the signed
		// artifact — otherwise cosign verifies the signature against the
		// bundle itself and reports "invalid signature".
		u := strings.TrimSuffix(bundleURL, ".sigstore.json")
		return strings.TrimSuffix(u, ".sig.bundle")
	}
	return strings.TrimSuffix(sigURL, ".sig")
}

// downloadChecksums fetches a release's checksums.txt into the
// signatures/ directory. Same size budget as a signature payload —
// checksums.txt is small (one short line per artifact).
func (s *Store) downloadChecksums(ctx context.Context, rawURL string) (string, error) {
	// Reuse the signature-download path: same network policy, same
	// 64 KB cap, same staging directory. The on-disk filename is
	// arbitrary; cosign verify-blob takes the path directly.
	return s.downloadSignature(ctx, rawURL)
}

// verifyChecksumsListsArtifact opens a GoReleaser-style checksums.txt
// (one `<hex>  <filename>` per line) and confirms the registry
// artifact's filename appears with the registry-advertised digest.
// Returns (mismatch=true, nil) when the file is well-formed but the
// artifact isn't listed, or its hex disagrees with artifactDigest.
// Returns (false, err) only on parse / IO failure.
func verifyChecksumsListsArtifact(checksumsPath, artifactURL, artifactDigest string) (bool, error) {
	body, err := os.ReadFile(checksumsPath)
	if err != nil {
		return false, fmt.Errorf("reading checksums.txt: %w", err)
	}
	wantHex := strings.ToLower(strings.TrimPrefix(artifactDigest, "sha256:"))
	artifactName := filepath.Base(artifactURL)
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		gotHex := strings.ToLower(fields[0])
		gotName := fields[1]
		if gotName != artifactName {
			continue
		}
		if gotHex != wantHex {
			return true, nil
		}
		return false, nil
	}
	return true, nil
}

// isRealDigest reports whether a registry-stamped digest is a usable
// SHA-256. Empty values, the marketplace placeholder "sha256:tbd", and
// values shorter than a real hex digest are all rejected so install
// cannot proceed against an unsigned-and-unhashed artifact entry.
func isRealDigest(d string) bool {
	if d == "" {
		return false
	}
	hex := strings.TrimPrefix(d, "sha256:")
	if len(hex) < 32 {
		return false
	}
	for _, r := range hex {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'f':
		case r >= 'A' && r <= 'F':
		default:
			return false
		}
	}
	return true
}
