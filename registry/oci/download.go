package oci

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
)

// ErrSizeExceeded indicates an artifact exceeds the maximum download size.
var ErrSizeExceeded = errors.New("artifact exceeds maximum download size")

// download fetches a URL to a temporary file in the store's tmp directory.
// It enforces the configured maximum download size. On success it returns the
// temporary file path and the number of bytes written. The caller is responsible
// for cleaning up or renaming the temp file.
func (s *Store) download(ctx context.Context, rawURL string, expectedSize int64) (tmpPath string, written int64, err error) {
	finalURL, err := s.rewriteURL(rawURL)
	if err != nil {
		return "", 0, fmt.Errorf("rewriting URL: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, finalURL, nil)
	if err != nil {
		return "", 0, fmt.Errorf("creating request: %w", err)
	}

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", 0, fmt.Errorf("downloading artifact: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return "", 0, fmt.Errorf("download returned HTTP %d", resp.StatusCode)
	}

	tmpDir := filepath.Join(s.cacheDir, "tmp")
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return "", 0, fmt.Errorf("creating tmp dir: %w", err)
	}

	f, err := os.CreateTemp(tmpDir, "download-*")
	if err != nil {
		return "", 0, fmt.Errorf("creating temp file: %w", err)
	}
	tmpPath = f.Name()

	defer func() {
		f.Close()
		if err != nil {
			_ = os.Remove(tmpPath)
			tmpPath = ""
		}
	}()

	// Read up to maxSize+1 to detect oversized responses.
	limit := s.maxSize + 1
	written, err = io.Copy(f, io.LimitReader(resp.Body, limit))
	if err != nil {
		return tmpPath, written, fmt.Errorf("reading response body: %w", err)
	}

	if written > s.maxSize {
		err = ErrSizeExceeded
		return tmpPath, written, err
	}

	if err = f.Close(); err != nil {
		return tmpPath, written, fmt.Errorf("closing temp file: %w", err)
	}

	return tmpPath, written, nil
}

// rewriteURL replaces the scheme+host of a URL with the configured mirror base.
// If no mirror is configured, the original URL is returned unchanged.
func (s *Store) rewriteURL(original string) (string, error) {
	if s.mirrorBase == "" {
		return original, nil
	}

	origParsed, err := url.Parse(original)
	if err != nil {
		return "", fmt.Errorf("parsing original URL: %w", err)
	}

	mirrorParsed, err := url.Parse(s.mirrorBase)
	if err != nil {
		return "", fmt.Errorf("parsing mirror base: %w", err)
	}

	origParsed.Scheme = mirrorParsed.Scheme
	origParsed.Host = mirrorParsed.Host
	return origParsed.String(), nil
}
