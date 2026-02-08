// Package oci provides content-addressed artifact storage for Hardline plugins.
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
	"time"

	"github.com/felixgeelhaar/hardline/registry"
	"github.com/felixgeelhaar/hardline/registry/trust"
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
		cacheDir:   filepath.Join(os.Getenv("HOME"), ".hardline", "cache", "artifacts"),
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
func (s *Store) Fetch(ctx context.Context, name string, ve registry.VersionEntry) (*InstalledArtifact, error) {
	// 1. Select platform-appropriate artifact.
	artifact, err := SelectArtifact(ve.Artifacts)
	if err != nil {
		return nil, fmt.Errorf("selecting artifact for %s: %w", name, err)
	}

	return s.fetchArtifact(ctx, name, ve, artifact)
}

// FetchFor downloads an artifact for a specific OS/arch combination.
func (s *Store) FetchFor(ctx context.Context, name string, ve registry.VersionEntry, goos, goarch string) (*InstalledArtifact, error) {
	artifact, err := SelectArtifactFor(ve.Artifacts, goos, goarch)
	if err != nil {
		return nil, fmt.Errorf("selecting artifact for %s (%s/%s): %w", name, goos, goarch, err)
	}

	return s.fetchArtifact(ctx, name, ve, artifact)
}

func (s *Store) fetchArtifact(ctx context.Context, name string, ve registry.VersionEntry, artifact *registry.PlatformArtifact) (*InstalledArtifact, error) {
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
		// Look for a binary with the plugin base name in the extracted directory.
		installed.BinaryPath = filepath.Join(extractDir, filepath.Base(name))

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
