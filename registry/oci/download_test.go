package oci

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"
)

func TestDownloadSuccess(t *testing.T) {
	content := []byte("binary content for download test")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	tmpDir := t.TempDir()
	s := NewStore(
		WithCacheDir(tmpDir),
		WithHTTPClient(srv.Client()),
	)

	tmpPath, written, err := s.download(context.Background(), srv.URL+"/plugin.tar.gz", int64(len(content)))
	if err != nil {
		t.Fatalf("download: %v", err)
	}

	if written != int64(len(content)) {
		t.Errorf("written = %d, want %d", written, len(content))
	}

	if tmpPath == "" {
		t.Fatal("tmpPath is empty")
	}

	// Verify temp file is inside the cache tmp directory.
	tmpDir2, err := filepath.EvalSymlinks(tmpDir)
	if err != nil {
		t.Fatalf("EvalSymlinks: %v", err)
	}
	tmpPathReal, err := filepath.EvalSymlinks(filepath.Dir(tmpPath))
	if err != nil {
		t.Fatalf("EvalSymlinks tmpPath: %v", err)
	}
	wantDir, err := filepath.EvalSymlinks(filepath.Join(tmpDir2, "tmp"))
	if err != nil {
		// tmp dir might have been resolved already
		wantDir = filepath.Join(tmpDir2, "tmp")
	}
	if tmpPathReal != wantDir {
		t.Errorf("temp file dir = %q, want under %q", tmpPathReal, wantDir)
	}
}

func TestDownloadHTTP404(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	}))
	defer srv.Close()

	s := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
	)

	_, _, err := s.download(context.Background(), srv.URL+"/missing", 0)
	if err == nil {
		t.Fatal("expected error for 404")
	}
}

func TestDownloadHTTP500(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	s := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
	)

	_, _, err := s.download(context.Background(), srv.URL+"/error", 0)
	if err == nil {
		t.Fatal("expected error for 500")
	}
}

func TestDownloadSizeExceeded(t *testing.T) {
	content := make([]byte, 1024)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(content)
	}))
	defer srv.Close()

	s := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
		WithMaxDownloadSize(512), // limit is smaller than content
	)

	_, _, err := s.download(context.Background(), srv.URL+"/big", int64(len(content)))
	if !errors.Is(err, ErrSizeExceeded) {
		t.Errorf("error = %v, want %v", err, ErrSizeExceeded)
	}
}

func TestDownloadContextCancellation(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Slow response to allow cancellation.
		time.Sleep(5 * time.Second)
		w.Write([]byte("too late"))
	}))
	defer srv.Close()

	s := NewStore(
		WithCacheDir(t.TempDir()),
		WithHTTPClient(srv.Client()),
	)

	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately.

	_, _, err := s.download(ctx, srv.URL+"/slow", 100)
	if err == nil {
		t.Fatal("expected error for cancelled context")
	}
}

func TestRewriteURL(t *testing.T) {
	s := NewStore(
		WithCacheDir(t.TempDir()),
		WithMirrorBase("https://mirror.internal:8443"),
	)

	got, err := s.rewriteURL("https://registry.nox-hq.dev/plugins/scanner/v1.0.0/linux-amd64.tar.gz")
	if err != nil {
		t.Fatalf("rewriteURL: %v", err)
	}

	want := "https://mirror.internal:8443/plugins/scanner/v1.0.0/linux-amd64.tar.gz"
	if got != want {
		t.Errorf("rewriteURL = %q, want %q", got, want)
	}
}

func TestRewriteURLNoMirror(t *testing.T) {
	s := NewStore(WithCacheDir(t.TempDir()))

	original := "https://registry.nox-hq.dev/plugins/scanner.tar.gz"
	got, err := s.rewriteURL(original)
	if err != nil {
		t.Fatalf("rewriteURL: %v", err)
	}
	if got != original {
		t.Errorf("rewriteURL = %q, want %q (passthrough)", got, original)
	}
}

func TestRewriteURLPreservesPath(t *testing.T) {
	s := NewStore(
		WithCacheDir(t.TempDir()),
		WithMirrorBase("http://local:9000"),
	)

	got, err := s.rewriteURL("https://example.com/deep/path/to/file.tar.gz?sig=abc")
	if err != nil {
		t.Fatalf("rewriteURL: %v", err)
	}

	want := "http://local:9000/deep/path/to/file.tar.gz?sig=abc"
	if got != want {
		t.Errorf("rewriteURL = %q, want %q", got, want)
	}
}
