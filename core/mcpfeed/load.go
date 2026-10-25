package mcpfeed

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox-core/slopfeed"
)

const (
	// maxFeedSize bounds a fetched feed. The feed lists advisories for
	// MCP-classified packages: megabytes at the very most.
	maxFeedSize = 16 * 1024 * 1024
	// maxStatusSize bounds the status document read to explain a 404.
	maxStatusSize = 64 * 1024
	httpTimeout   = 30 * time.Second
	// DefaultRefresh is how long a cached feed is fresh. The service publishes
	// daily.
	DefaultRefresh = 24 * time.Hour
)

// Options configures Load.
type Options struct {
	// URL is the feed location (http or https).
	URL string
	// CacheDir holds verified feed bytes. Empty means $HOME/.nox/cache/mcpfeed.
	CacheDir string
	// TTL is how long a cached copy is fresh; within it no request is made.
	TTL time.Duration
	// Offline forbids the network: only a verified cache is used.
	Offline bool
	// HTTPClient overrides the default client (tests).
	HTTPClient *http.Client
	// Verify checks digest-then-signature under the pinned key. Required.
	Verify slopfeed.SignatureVerifier
}

// Loaded is a verified feed and where it came from.
type Loaded struct {
	*Feed
	// FromCache is set when the bytes were read from the local cache.
	FromCache bool
	// RefreshErr is why a refresh was attempted and failed, when a cached copy
	// was used instead. The copy verified; it may be older than the service's.
	RefreshErr error
}

// NotPublishedError means the service answered 404: it does not serve the feed,
// or has not published one yet. That is the SERVICE having nothing to say, which
// is different from the feed saying there are no advisories.
type NotPublishedError struct {
	// Reason is what the service said about itself (its status document's
	// disabled_reason, or its 404 message), when it said anything.
	Reason string
}

func (e *NotPublishedError) Error() string {
	if e.Reason != "" {
		return "the service has not published an MCP advisory feed: " + e.Reason
	}
	return "the service has not published an MCP advisory feed"
}

// Load fetches, verifies and caches the feed, failing closed: bytes are cached
// only after they verify, and cached bytes are re-verified on every read.
//
//   - Offline: a verified cache or an error.
//   - A fresh cache (within TTL): no request.
//   - Otherwise: fetch; on a network failure fall back to a verified cache and
//     say so in RefreshErr. A fetched feed that FAILS verification is never
//     papered over with the cache: that is a tampered answer, surfaced as such.
//   - A 404 is *NotPublishedError, not a network failure.
func Load(ctx context.Context, opts Options) (*Loaded, error) {
	if err := validateURL(opts.URL); err != nil {
		return nil, err
	}
	if opts.Verify == nil {
		return nil, errors.New("mcp feed: no pinned public key, so the feed cannot be verified")
	}
	path := cachePath(opts.CacheDir, opts.URL)

	if opts.Offline {
		l, err := readCache(path, opts.Verify)
		if err != nil {
			return nil, fmt.Errorf("offline: no usable cached MCP advisory feed for %s: %w", opts.URL, err)
		}
		return l, nil
	}
	if opts.TTL > 0 && !stale(path, opts.TTL) {
		if l, err := readCache(path, opts.Verify); err == nil {
			return l, nil
		}
	}

	f, err := fetch(ctx, opts, path)
	if err == nil {
		return &Loaded{Feed: f}, nil
	}
	if isVerificationFailure(err) {
		return nil, err
	}
	if l, cerr := readCache(path, opts.Verify); cerr == nil {
		l.RefreshErr = err
		return l, nil
	}
	return nil, err
}

func isVerificationFailure(err error) bool {
	return errors.Is(err, ErrDigest) || errors.Is(err, ErrSignature) || errors.Is(err, ErrUnsigned) || errors.Is(err, ErrSchema)
}

func validateURL(raw string) error {
	if raw == "" {
		return errors.New("MCP advisory feed URL is empty")
	}
	u, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("invalid MCP advisory feed URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("MCP advisory feed URL must be an absolute http(s) URL, got %q", raw)
	}
	return nil
}

func cachePath(dir, feedURL string) string {
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil || home == "" {
			home = os.Getenv("HOME")
		}
		dir = filepath.Join(home, ".nox", "cache", "mcpfeed")
	}
	h := sha256.Sum256([]byte(feedURL))
	return filepath.Join(dir, hex.EncodeToString(h[:8])+".json")
}

func stale(path string, ttl time.Duration) bool {
	info, err := os.Stat(path)
	return err != nil || time.Since(info.ModTime()) > ttl
}

func readCache(path string, verify slopfeed.SignatureVerifier) (*Loaded, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is derived from the feed URL under the cache dir
	if err != nil {
		return nil, err
	}
	f, err := Parse(data, verify)
	if err != nil {
		return nil, err
	}
	return &Loaded{Feed: f, FromCache: true}, nil
}

func fetch(ctx context.Context, opts Options, cache string) (*Feed, error) {
	client := opts.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: httpTimeout}
	}
	resp, err := get(ctx, client, opts.URL)
	if err != nil {
		return nil, fmt.Errorf("fetching MCP advisory feed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusNotFound {
		return nil, &NotPublishedError{Reason: notPublishedReason(ctx, client, opts.URL, resp)}
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("MCP advisory feed server returned HTTP %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxFeedSize+1))
	if err != nil {
		return nil, fmt.Errorf("reading MCP advisory feed: %w", err)
	}
	if len(body) > maxFeedSize {
		return nil, fmt.Errorf("MCP advisory feed exceeds %d bytes", maxFeedSize)
	}
	f, err := Parse(body, opts.Verify)
	if err != nil {
		return nil, fmt.Errorf("verifying fetched MCP advisory feed: %w", err)
	}
	// Only verified bytes are persisted; a write failure loses the offline copy
	// and nothing else.
	_ = writeCache(cache, body)
	return f, nil
}

func get(ctx context.Context, client *http.Client, target string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, http.NoBody)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "nox-mcpfeed-client")
	req.Header.Set("Accept", "application/json")
	return client.Do(req)
}

// notPublishedReason explains a 404: the service's status document names why the
// job is disabled ("no signing key yet"), the 404 body names the condition.
func notPublishedReason(ctx context.Context, client *http.Client, feedURL string, notFound *http.Response) string {
	var body struct {
		Error          string `json:"error"`
		DisabledReason string `json:"disabled_reason"`
	}
	b, _ := io.ReadAll(io.LimitReader(notFound.Body, maxStatusSize))
	_ = json.Unmarshal(b, &body)
	reason := body.Error
	if resp, err := get(ctx, client, strings.TrimRight(feedURL, "/")+"/status"); err == nil {
		defer func() { _ = resp.Body.Close() }()
		if resp.StatusCode == http.StatusOK {
			sb, _ := io.ReadAll(io.LimitReader(resp.Body, maxStatusSize))
			var st struct {
				DisabledReason string `json:"disabled_reason"`
			}
			if json.Unmarshal(sb, &st) == nil && st.DisabledReason != "" {
				reason = st.DisabledReason
			}
		}
	}
	return reason
}

func writeCache(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
