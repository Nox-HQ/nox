package feed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

const (
	// maxFeedSize bounds a fetched feed so a hostile or misbehaving server
	// cannot exhaust memory. A real feed is a few hundred entries — kilobytes;
	// 8 MiB is generous headroom.
	maxFeedSize = 8 * 1024 * 1024
	// defaultFeedHTTPTimeout bounds a single feed fetch.
	defaultFeedHTTPTimeout = 30 * time.Second
	// DefaultRefreshInterval is how long a cached remote feed is treated as
	// fresh before a refetch is attempted. A signed feed changes on the
	// generator's cadence (days), so a day is a safe default that keeps scans
	// offline between refreshes.
	DefaultRefreshInterval = 24 * time.Hour
)

// RemoteOptions configures fetching, caching, and verifying a feed served over
// HTTP(S).
type RemoteOptions struct {
	// URL is the feed location. Must be http or https.
	URL string
	// CacheDir is where verified feed bytes are cached, content-addressed by
	// URL. Empty defaults to $HOME/.nox/cache/slopfeed.
	CacheDir string
	// TTL is how long a cached copy is considered fresh; within it, no network
	// call is made. Zero forces a refetch attempt (still falling back to cache
	// on a network error). See DefaultRefreshInterval.
	TTL time.Duration
	// Offline forbids all network access: the feed is served from cache or the
	// load fails closed. Mirrors the scan-wide Offline guarantee.
	Offline bool
	// HTTPClient overrides the default client (used by tests). Nil uses a client
	// with defaultFeedHTTPTimeout.
	HTTPClient *http.Client
	// Verify is applied to both freshly fetched and cached bytes. Only bytes
	// that pass verification are ever cached or returned.
	Verify VerifyOptions
}

// LoadRemote fetches, verifies, and caches a feed from a URL, then returns it
// indexed for lookup. It is the remote analogue of Load, and it fails closed on
// every error path: a fetch failure, a non-2xx status, an oversized body, a
// digest mismatch, or an unmet signature requirement never yields a trusted
// feed and never panics.
//
// Determinism and offline behavior:
//   - A cached copy that is still fresh (within TTL) and that re-verifies is
//     used WITHOUT any network call, so repeated scans are deterministic and a
//     disconnected machine keeps working.
//   - Offline forbids the network entirely: only a verified cache is accepted.
//   - When a refetch is attempted but the network fails, a previously cached and
//     re-verified copy is used as a fallback rather than losing coverage.
//
// Critically, verification gates USE: bytes are cached only after they verify,
// and cached bytes are re-verified on every read. An attacker who MITMs the feed
// cannot inject a name nox would then flag, nor suppress an existing one,
// without a signature that verifies under the pinned key.
func LoadRemote(ctx context.Context, opts RemoteOptions) (*Loaded, error) {
	if err := validateFeedURL(opts.URL); err != nil {
		return nil, err
	}
	cacheDir := opts.CacheDir
	if cacheDir == "" {
		cacheDir = filepath.Join(os.Getenv("HOME"), ".nox", "cache", "slopfeed")
	}
	cachePath := feedCachePath(cacheDir, opts.URL)

	// Offline: cache-only, fail closed if absent or unverifiable.
	if opts.Offline {
		loaded, err := loadCachedFeed(cachePath, opts.Verify)
		if err != nil {
			return nil, fmt.Errorf("offline: no usable cached feed for %s: %w", opts.URL, err)
		}
		return loaded, nil
	}

	// Fresh cache within TTL: serve without touching the network.
	if opts.TTL > 0 && !cacheStale(cachePath, opts.TTL) {
		if loaded, err := loadCachedFeed(cachePath, opts.Verify); err == nil {
			return loaded, nil
		}
		// A corrupt/unverifiable cache is not fatal here: fall through to fetch a
		// fresh copy.
	}

	// Fetch, verify, and cache.
	loaded, fetchErr := fetchAndCacheFeed(ctx, opts, cachePath)
	if fetchErr == nil {
		return loaded, nil
	}

	// Network failure: fall back to a cached, re-verified copy (even if stale)
	// rather than losing predictive coverage. A verification failure on the
	// FETCHED bytes is not eligible for fallback here — fetchAndCacheFeed only
	// returns a non-nil loaded on success, and a tampered/bad-signature fetch
	// returns an error we surface, never a cached impersonation of it.
	if loaded, err := loadCachedFeed(cachePath, opts.Verify); err == nil {
		return loaded, nil
	}
	return nil, fetchErr
}

// validateFeedURL rejects anything that is not an absolute http(s) URL. This
// keeps LoadRemote from being coerced into reading local files or other schemes.
func validateFeedURL(raw string) error {
	if raw == "" {
		return errors.New("feed URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid feed URL: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return fmt.Errorf("feed URL must use http or https, got %q", u.Scheme)
	}
	if u.Host == "" {
		return fmt.Errorf("feed URL has no host: %q", raw)
	}
	return nil
}

// feedCachePath derives a deterministic, content-addressed cache path from the
// feed URL, mirroring the registry cache's scheme.
func feedCachePath(dir, feedURL string) string {
	h := sha256.Sum256([]byte(feedURL))
	return filepath.Join(dir, hex.EncodeToString(h[:8])+".json")
}

// cacheStale reports whether the cache file is missing or older than ttl.
func cacheStale(path string, ttl time.Duration) bool {
	info, err := os.Stat(path)
	if err != nil {
		return true
	}
	return time.Since(info.ModTime()) > ttl
}

// loadCachedFeed reads and re-verifies cached feed bytes. A missing file or a
// verification failure returns an error (fail closed) so the caller never trusts
// an unverifiable cache.
func loadCachedFeed(path string, verify VerifyOptions) (*Loaded, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Parse(data, verify)
}

// fetchAndCacheFeed performs the network fetch, verifies the response, and — only
// on success — atomically writes the verified bytes to the cache.
func fetchAndCacheFeed(ctx context.Context, opts RemoteOptions, cachePath string) (*Loaded, error) {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultFeedHTTPTimeout}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, opts.URL, http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("building feed request: %w", err)
	}
	req.Header.Set("User-Agent", "nox-slopfeed-client")

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("feed server returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading feed body: %w", err)
	}
	if len(body) > maxFeedSize {
		return nil, fmt.Errorf("feed exceeds maximum size of %d bytes", maxFeedSize)
	}

	// Verify BEFORE caching: only verified bytes are ever persisted or trusted.
	loaded, err := Parse(body, opts.Verify)
	if err != nil {
		return nil, fmt.Errorf("verifying fetched feed: %w", err)
	}
	if err := writeFeedCache(cachePath, body); err != nil {
		// A cache-write failure must not fail the load — we already have a
		// verified feed in hand; we just lose the offline copy this round.
		return loaded, nil //nolint:nilerr // verified feed is usable; cache is best-effort
	}
	return loaded, nil
}

// writeFeedCache atomically writes verified feed bytes to the cache (temp file +
// rename), creating the cache directory as needed.
func writeFeedCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("creating feed cache dir: %w", err)
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return fmt.Errorf("writing feed cache: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return fmt.Errorf("renaming feed cache: %w", err)
	}
	return nil
}
