package oci

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/registry/trust"
)

// buildTarGz creates an in-memory tar.gz from the given file entries.
func buildTarGz(t *testing.T, entries map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	gw := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gw)

	for name, content := range entries {
		if err := tw.WriteHeader(&tar.Header{
			Name: name,
			Mode: 0o755,
			Size: int64(len(content)),
		}); err != nil {
			t.Fatalf("writing tar header: %v", err)
		}
		if _, err := tw.Write([]byte(content)); err != nil {
			t.Fatalf("writing tar content: %v", err)
		}
	}

	tw.Close()
	gw.Close()
	return buf.Bytes()
}

// sha256Digest computes "sha256:<hex>" for the given data.
func sha256Digest(data []byte) string {
	h := sha256.Sum256(data)
	return "sha256:" + hex.EncodeToString(h[:])
}

func TestStoreFetchFullFlow(t *testing.T) {
	tarGzData := buildTarGz(t, map[string]string{
		"plugin": "#!/bin/sh\necho hello",
	})
	digest := sha256Digest(tarGzData)

	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Write(tarGzData)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	store := NewStore(
		WithCacheDir(cacheDir),
		WithHTTPClient(srv.Client()),
		WithVerifier(trust.NewVerifier()),
	)

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{
				OS:     "darwin",
				Arch:   "arm64",
				URL:    srv.URL + "/plugin-darwin-arm64.tar.gz",
				Size:   int64(len(tarGzData)),
				Digest: digest,
			},
			{
				OS:     "linux",
				Arch:   "amd64",
				URL:    srv.URL + "/plugin-linux-amd64.tar.gz",
				Size:   int64(len(tarGzData)),
				Digest: digest,
			},
		},
	}

	ctx := context.Background()

	// Use FetchFor to test a specific platform.
	installed, err := store.FetchFor(ctx, "test/plugin", ve, "linux", "amd64")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if installed.PluginName != "test/plugin" {
		t.Errorf("PluginName = %q, want %q", installed.PluginName, "test/plugin")
	}
	if installed.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", installed.Version, "1.0.0")
	}
	if installed.OS != "linux" {
		t.Errorf("OS = %q, want %q", installed.OS, "linux")
	}
	if installed.Arch != "amd64" {
		t.Errorf("Arch = %q, want %q", installed.Arch, "amd64")
	}
	if installed.Digest != digest {
		t.Errorf("Digest = %q, want %q", installed.Digest, digest)
	}
	if installed.Format != FormatTarGz {
		t.Errorf("Format = %d, want FormatTarGz", installed.Format)
	}
	if installed.ExtractDir == "" {
		t.Error("ExtractDir should be set for tar.gz")
	}
	if installed.Size != int64(len(tarGzData)) {
		t.Errorf("Size = %d, want %d", installed.Size, len(tarGzData))
	}

	// Verify the blob was stored.
	if !store.Has(digest) {
		t.Error("Has() should return true after Fetch")
	}

	// Verify BlobPath sharding.
	blobPath := store.BlobPath(digest)
	hexVal := digest[len("sha256:"):]
	wantShard := filepath.Join(cacheDir, "sha256", hexVal[:2], hexVal)
	blobPathReal, _ := filepath.EvalSymlinks(blobPath)
	wantShardReal, _ := filepath.EvalSymlinks(wantShard)
	if blobPathReal != wantShardReal {
		t.Errorf("BlobPath = %q, want %q", blobPathReal, wantShardReal)
	}

	if requestCount.Load() != 1 {
		t.Errorf("HTTP requests = %d, want 1", requestCount.Load())
	}
}

func TestStoreFetchCacheHit(t *testing.T) {
	tarGzData := buildTarGz(t, map[string]string{
		"plugin": "cached binary",
	})
	digest := sha256Digest(tarGzData)

	var requestCount atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestCount.Add(1)
		w.Write(tarGzData)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	store := NewStore(
		WithCacheDir(cacheDir),
		WithHTTPClient(srv.Client()),
	)

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{OS: "linux", Arch: "amd64", URL: srv.URL + "/plugin.tar.gz", Size: int64(len(tarGzData)), Digest: digest},
		},
	}

	ctx := context.Background()

	// First fetch: downloads.
	_, err := store.FetchFor(ctx, "test/plugin", ve, "linux", "amd64")
	if err != nil {
		t.Fatalf("first Fetch: %v", err)
	}

	if requestCount.Load() != 1 {
		t.Fatalf("first Fetch HTTP requests = %d, want 1", requestCount.Load())
	}

	// Second fetch: should use cache, no HTTP request.
	installed2, err := store.FetchFor(ctx, "test/plugin", ve, "linux", "amd64")
	if err != nil {
		t.Fatalf("second Fetch: %v", err)
	}

	if requestCount.Load() != 1 {
		t.Errorf("second Fetch HTTP requests = %d, want 1 (cache hit)", requestCount.Load())
	}

	if installed2.PluginName != "test/plugin" {
		t.Errorf("cached result PluginName = %q", installed2.PluginName)
	}
}

func TestStoreFetchDigestMismatch(t *testing.T) {
	tarGzData := buildTarGz(t, map[string]string{
		"plugin": "real data",
	})

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarGzData)
	}))
	defer srv.Close()

	store := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
	)

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{
				OS:     "linux",
				Arch:   "amd64",
				URL:    srv.URL + "/plugin.tar.gz",
				Size:   int64(len(tarGzData)),
				Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000",
			},
		},
	}

	_, err := store.FetchFor(context.Background(), "test/plugin", ve, "linux", "amd64")
	if !errors.Is(err, ErrDigestMismatch) {
		t.Errorf("error = %v, want %v", err, ErrDigestMismatch)
	}
}

func TestStoreFetchRawBinary(t *testing.T) {
	binaryData := []byte("#!/bin/sh\necho hello world")
	digest := sha256Digest(binaryData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(binaryData)
	}))
	defer srv.Close()

	store := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
	)

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{OS: "linux", Arch: "amd64", URL: srv.URL + "/plugin", Size: int64(len(binaryData)), Digest: digest},
		},
	}

	installed, err := store.FetchFor(context.Background(), "test/plugin", ve, "linux", "amd64")
	if err != nil {
		t.Fatalf("Fetch raw binary: %v", err)
	}

	if installed.Format != FormatRawBinary {
		t.Errorf("Format = %d, want FormatRawBinary", installed.Format)
	}
	if installed.ExtractDir != "" {
		t.Errorf("ExtractDir should be empty for raw binary, got %q", installed.ExtractDir)
	}
	if installed.BinaryPath != installed.BlobPath {
		t.Errorf("BinaryPath = %q, want BlobPath %q", installed.BinaryPath, installed.BlobPath)
	}

	// Verify the binary is executable.
	info, err := os.Stat(installed.BinaryPath)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Error("binary should be executable")
	}
}

func TestStoreFetchTrustVerification(t *testing.T) {
	tarGzData := buildTarGz(t, map[string]string{
		"plugin": "plugin binary",
	})
	digest := sha256Digest(tarGzData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarGzData)
	}))
	defer srv.Close()

	store := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
		WithVerifier(trust.NewVerifier()),
	)

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{OS: "linux", Arch: "amd64", URL: srv.URL + "/plugin.tar.gz", Size: int64(len(tarGzData)), Digest: digest},
		},
	}

	installed, err := store.FetchFor(context.Background(), "test/plugin", ve, "linux", "amd64")
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	// Without signature, trust level should be unverified.
	if installed.VerifyResult.TrustLevel != trust.TrustUnverified {
		t.Errorf("TrustLevel = %v, want %v", installed.VerifyResult.TrustLevel, trust.TrustUnverified)
	}

	// Digest should match.
	if !installed.VerifyResult.DigestMatch {
		t.Error("DigestMatch should be true")
	}
}

func TestStoreHasAndBlobPath(t *testing.T) {
	store := NewStore(WithCacheDir(t.TempDir()))

	digest := "sha256:abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789"

	if store.Has(digest) {
		t.Error("Has should return false for nonexistent digest")
	}

	// Create the blob file.
	blobPath := store.BlobPath(digest)
	if err := os.MkdirAll(filepath.Dir(blobPath), 0o755); err != nil {
		t.Fatalf("MkdirAll: %v", err)
	}
	if err := os.WriteFile(blobPath, []byte("test"), 0o644); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	if !store.Has(digest) {
		t.Error("Has should return true after creating blob")
	}
}

func TestStoreFetchNoPlatformMatch(t *testing.T) {
	store := NewStore(WithCacheDir(t.TempDir()))

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{OS: "freebsd", Arch: "riscv64"},
		},
	}

	_, err := store.FetchFor(context.Background(), "test/plugin", ve, "linux", "amd64")
	if !errors.Is(err, ErrNoPlatformMatch) {
		t.Errorf("error = %v, want %v", err, ErrNoPlatformMatch)
	}
}

func TestNewStoreDefaults(t *testing.T) {
	store := NewStore()

	if store.maxSize != defaultMaxDownloadSize {
		t.Errorf("maxSize = %d, want %d", store.maxSize, defaultMaxDownloadSize)
	}
	if store.httpClient == nil {
		t.Error("httpClient should not be nil")
	}
	if store.verifier == nil {
		t.Error("verifier should not be nil")
	}
	if store.mirrorBase != "" {
		t.Errorf("mirrorBase = %q, want empty", store.mirrorBase)
	}
}

func TestNewStoreOptions(t *testing.T) {
	cacheDir := t.TempDir()
	hc := &http.Client{Timeout: 10 * time.Second}
	v := trust.NewVerifier()

	store := NewStore(
		WithCacheDir(cacheDir),
		WithHTTPClient(hc),
		WithVerifier(v),
		WithMaxDownloadSize(1024),
		WithMirrorBase("https://mirror.example.com"),
	)

	cacheReal, _ := filepath.EvalSymlinks(cacheDir)
	storeReal, _ := filepath.EvalSymlinks(store.cacheDir)
	if storeReal != cacheReal {
		t.Errorf("cacheDir = %q, want %q", storeReal, cacheReal)
	}
	if store.httpClient != hc {
		t.Error("httpClient not set")
	}
	if store.verifier != v {
		t.Error("verifier not set")
	}
	if store.maxSize != 1024 {
		t.Errorf("maxSize = %d, want 1024", store.maxSize)
	}
	if store.mirrorBase != "https://mirror.example.com" {
		t.Errorf("mirrorBase = %q", store.mirrorBase)
	}
}

// TestStoreFetch tests the Fetch method which uses runtime platform selection.
func TestStoreFetch(t *testing.T) {
	tarGzData := buildTarGz(t, map[string]string{
		"plugin": "#!/bin/sh\necho hello",
	})
	digest := sha256Digest(tarGzData)

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarGzData)
	}))
	defer srv.Close()

	cacheDir := t.TempDir()
	store := NewStore(
		WithCacheDir(cacheDir),
		WithHTTPClient(srv.Client()),
		WithVerifier(trust.NewVerifier()),
	)

	ve := registry.VersionEntry{
		Version:    "2.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{
				OS:     runtime.GOOS,
				Arch:   runtime.GOARCH,
				URL:    srv.URL + "/plugin-current.tar.gz",
				Size:   int64(len(tarGzData)),
				Digest: digest,
			},
		},
	}

	ctx := context.Background()
	installed, err := store.Fetch(ctx, "test/plugin", ve)
	if err != nil {
		t.Fatalf("Fetch: %v", err)
	}

	if installed.PluginName != "test/plugin" {
		t.Errorf("PluginName = %q, want %q", installed.PluginName, "test/plugin")
	}
	if installed.Version != "2.0.0" {
		t.Errorf("Version = %q, want %q", installed.Version, "2.0.0")
	}
	if installed.OS != runtime.GOOS {
		t.Errorf("OS = %q, want %q", installed.OS, runtime.GOOS)
	}
	if installed.Arch != runtime.GOARCH {
		t.Errorf("Arch = %q, want %q", installed.Arch, runtime.GOARCH)
	}
}

// TestStoreFetchNoPlatformMatchForFetch tests Fetch when no artifact matches
// the runtime platform.
func TestStoreFetchNoPlatformMatchForFetch(t *testing.T) {
	store := NewStore(WithCacheDir(t.TempDir()))

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{OS: "plan9", Arch: "mips"},
		},
	}

	_, err := store.Fetch(context.Background(), "test/plugin", ve)
	if !errors.Is(err, ErrNoPlatformMatch) {
		t.Errorf("error = %v, want %v", err, ErrNoPlatformMatch)
	}
}

// TestDigestHex tests the digestHex function with various inputs.
func TestDigestHex(t *testing.T) {
	tests := []struct {
		name   string
		input  string
		want   string
	}{
		{
			name:  "standard sha256 prefix",
			input: "sha256:abcdef0123456789",
			want:  "abcdef0123456789",
		},
		{
			name:  "no prefix",
			input: "abcdef0123456789",
			want:  "abcdef0123456789",
		},
		{
			name:  "empty string",
			input: "",
			want:  "",
		},
		{
			name:  "just the prefix",
			input: "sha256:",
			want:  "sha256:",
		},
		{
			name:  "short string",
			input: "ab",
			want:  "ab",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := digestHex(tt.input)
			if got != tt.want {
				t.Errorf("digestHex(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

// TestBlobPathShortDigest tests BlobPath with a digest shorter than 2 hex chars.
func TestBlobPathShortDigest(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	// A digest with no prefix and less than 2 characters.
	got := store.BlobPath("x")
	want := filepath.Join(cacheDir, "sha256", "x")
	gotReal, _ := filepath.EvalSymlinks(filepath.Dir(got))
	wantReal, _ := filepath.EvalSymlinks(filepath.Dir(want))
	if gotReal != wantReal || filepath.Base(got) != filepath.Base(want) {
		t.Errorf("BlobPath(\"x\") = %q, want %q", got, want)
	}
}

// TestExtractPathShortDigest tests extractPath with a short digest.
func TestExtractPathShortDigest(t *testing.T) {
	cacheDir := t.TempDir()
	store := NewStore(WithCacheDir(cacheDir))

	got := store.extractPath("y")
	want := filepath.Join(cacheDir, "extracted", "y")
	gotReal, _ := filepath.EvalSymlinks(filepath.Dir(got))
	wantReal, _ := filepath.EvalSymlinks(filepath.Dir(want))
	if gotReal != wantReal || filepath.Base(got) != filepath.Base(want) {
		t.Errorf("extractPath(\"y\") = %q, want %q", got, want)
	}
}

// TestStoreFetchHTTPError tests fetchArtifact when the HTTP server returns an error.
func TestStoreFetchHTTPError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer srv.Close()

	store := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
	)

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{OS: "linux", Arch: "amd64", URL: srv.URL + "/plugin.tar.gz", Size: 100, Digest: "sha256:0000000000000000000000000000000000000000000000000000000000000000"},
		},
	}

	_, err := store.FetchFor(context.Background(), "test/plugin", ve, "linux", "amd64")
	if err == nil {
		t.Fatal("expected error for HTTP 503")
	}
}

// TestStoreFetchWithMirror tests that Fetch uses the mirror base URL for downloads.
func TestStoreFetchWithMirror(t *testing.T) {
	tarGzData := buildTarGz(t, map[string]string{
		"plugin": "#!/bin/sh\necho mirror",
	})
	digest := sha256Digest(tarGzData)

	// The mirror server that will actually receive the request.
	mirrorSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(tarGzData)
	}))
	defer mirrorSrv.Close()

	cacheDir := t.TempDir()
	store := NewStore(
		WithCacheDir(cacheDir),
		WithHTTPClient(mirrorSrv.Client()),
		WithVerifier(trust.NewVerifier()),
		WithMirrorBase(mirrorSrv.URL),
	)

	ve := registry.VersionEntry{
		Version:    "1.0.0",
		APIVersion: "v1",
		Artifacts: []registry.PlatformArtifact{
			{
				OS:     "linux",
				Arch:   "amd64",
				URL:    "https://original-registry.example.com/plugin.tar.gz",
				Size:   int64(len(tarGzData)),
				Digest: digest,
			},
		},
	}

	installed, err := store.FetchFor(context.Background(), "test/plugin", ve, "linux", "amd64")
	if err != nil {
		t.Fatalf("Fetch with mirror: %v", err)
	}

	if installed.PluginName != "test/plugin" {
		t.Errorf("PluginName = %q, want %q", installed.PluginName, "test/plugin")
	}
}
