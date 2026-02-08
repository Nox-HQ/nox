package registry

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

const (
	defaultCacheTTL    = 1 * time.Hour
	defaultHTTPTimeout = 30 * time.Second
	supportedSchema    = "1"
	maxIndexSize       = 10 * 1024 * 1024 // 10 MB
)

// Client fetches, caches, and queries plugin registry indexes.
type Client struct {
	sources    []Source
	cache      *fileCache
	httpClient *http.Client
}

// ClientOption is a functional option for configuring a Client.
type ClientOption func(*Client)

// WithCacheDir sets the directory for caching registry indexes.
func WithCacheDir(dir string) ClientOption {
	return func(c *Client) { c.cache.dir = dir }
}

// WithCacheTTL sets how long cached indexes are considered fresh.
func WithCacheTTL(ttl time.Duration) ClientOption {
	return func(c *Client) { c.cache.ttl = ttl }
}

// WithHTTPClient sets a custom HTTP client for registry fetches.
func WithHTTPClient(hc *http.Client) ClientOption {
	return func(c *Client) { c.httpClient = hc }
}

// NewClient creates a registry Client with the given options.
func NewClient(opts ...ClientOption) *Client {
	cacheDir := filepath.Join(os.Getenv("HOME"), ".hardline", "cache", "registry")

	c := &Client{
		cache:      newFileCache(cacheDir, defaultCacheTTL),
		httpClient: &http.Client{Timeout: defaultHTTPTimeout},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

// AddSource adds a registry source. Duplicate URLs are silently skipped.
func (c *Client) AddSource(s Source) error {
	if s.Name == "" {
		return errors.New("source name is required")
	}
	if s.URL == "" {
		return errors.New("source URL is required")
	}
	for _, existing := range c.sources {
		if existing.URL == s.URL {
			return nil
		}
	}
	c.sources = append(c.sources, s)
	return nil
}

// RemoveSource removes a registry source by name.
func (c *Client) RemoveSource(name string) error {
	for i, s := range c.sources {
		if s.Name == name {
			c.sources = append(c.sources[:i], c.sources[i+1:]...)
			return nil
		}
	}
	return fmt.Errorf("source %q not found", name)
}

// Sources returns all configured sources.
func (c *Client) Sources() []Source {
	out := make([]Source, len(c.sources))
	copy(out, c.sources)
	return out
}

// Refresh fetches fresh indexes from all sources, updating the cache.
func (c *Client) Refresh(ctx context.Context) error {
	var errs []error
	for _, src := range c.sources {
		idx, err := c.fetch(ctx, src)
		if err != nil {
			errs = append(errs, fmt.Errorf("source %q: %w", src.Name, err))
			continue
		}
		if err := c.cache.store(src, idx); err != nil {
			errs = append(errs, fmt.Errorf("caching %q: %w", src.Name, err))
		}
	}
	return errors.Join(errs...)
}

// Search returns plugins matching a query string (case-insensitive substring
// match on name or description) across all sources.
func (c *Client) Search(ctx context.Context, query string) ([]PluginEntry, error) {
	indexes, err := c.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	query = strings.ToLower(query)
	seen := make(map[string]bool)
	var results []PluginEntry

	for _, idx := range indexes {
		for _, p := range idx.Plugins {
			if seen[p.Name] {
				continue
			}
			if strings.Contains(strings.ToLower(p.Name), query) ||
				strings.Contains(strings.ToLower(p.Description), query) {
				seen[p.Name] = true
				results = append(results, p)
			}
		}
	}
	return results, nil
}

// ResolveOption configures the behavior of Resolve.
type ResolveOption func(*resolveConfig)

type resolveConfig struct {
	filter func(PluginEntry) bool
}

// WithFilter adds a filter that must return true for a plugin to be
// considered during resolution. This allows callers to enforce safety
// policies without coupling the registry package to the plugin package.
func WithFilter(fn func(PluginEntry) bool) ResolveOption {
	return func(rc *resolveConfig) { rc.filter = fn }
}

// Resolve finds the highest version of the named plugin that satisfies the
// given constraint string across all sources. Returns an error if no matching
// version is found.
func (c *Client) Resolve(ctx context.Context, name, constraint string, opts ...ResolveOption) (*VersionEntry, error) {
	var rc resolveConfig
	for _, opt := range opts {
		opt(&rc)
	}

	con, err := ParseConstraint(constraint)
	if err != nil {
		return nil, fmt.Errorf("invalid constraint: %w", err)
	}

	indexes, err := c.loadAll(ctx)
	if err != nil {
		return nil, err
	}

	var best *VersionEntry
	var bestVer Version

	for _, idx := range indexes {
		for _, p := range idx.Plugins {
			if p.Name != name {
				continue
			}
			if rc.filter != nil && !rc.filter(p) {
				continue
			}
			for i := range p.Versions {
				ve := &p.Versions[i]
				v, err := ParseVersion(ve.Version)
				if err != nil {
					continue
				}
				if !con.Match(v) {
					continue
				}
				if best == nil || v.Compare(bestVer) > 0 {
					best = ve
					bestVer = v
				}
			}
		}
	}

	if best == nil {
		return nil, fmt.Errorf("no version of %q matches constraint %q", name, constraint)
	}

	// Return a copy to prevent mutation.
	result := *best
	return &result, nil
}

// loadAll returns indexes for all sources, using cache when fresh and fetching
// otherwise.
func (c *Client) loadAll(ctx context.Context) ([]*Index, error) {
	var indexes []*Index
	var errs []error

	for _, src := range c.sources {
		idx, err := c.getIndex(ctx, src)
		if err != nil {
			errs = append(errs, fmt.Errorf("source %q: %w", src.Name, err))
			continue
		}
		indexes = append(indexes, idx)
	}

	if len(indexes) == 0 && len(errs) > 0 {
		return nil, errors.Join(errs...)
	}
	return indexes, nil
}

// getIndex returns the index for a source, using cache if fresh.
func (c *Client) getIndex(ctx context.Context, src Source) (*Index, error) {
	if !c.cache.isStale(src) {
		idx, err := c.cache.load(src)
		if err == nil {
			return idx, nil
		}
		// Cache corrupt or unreadable — fall through to fetch.
	}

	idx, err := c.fetch(ctx, src)
	if err != nil {
		// Try stale cache as fallback.
		cached, cacheErr := c.cache.load(src)
		if cacheErr == nil {
			return cached, nil
		}
		return nil, err
	}

	_ = c.cache.store(src, idx)
	return idx, nil
}

// fetch retrieves and validates a registry index from a source URL.
func (c *Client) fetch(ctx context.Context, src Source) (*Index, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, src.URL, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("fetching index: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("registry returned HTTP %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxIndexSize))
	if err != nil {
		return nil, fmt.Errorf("reading response: %w", err)
	}

	var idx Index
	if err := json.Unmarshal(body, &idx); err != nil {
		return nil, fmt.Errorf("parsing index: %w", err)
	}

	if idx.SchemaVersion != supportedSchema {
		return nil, fmt.Errorf("unsupported schema version %q (expected %q)", idx.SchemaVersion, supportedSchema)
	}

	return &idx, nil
}
