package npmtree

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// DefaultRegistry is the public npm registry.
const DefaultRegistry = "https://registry.npmjs.org"

// HTTPRegistry reads release history from an npm registry. Each package is
// asked once per HTTPRegistry; Requested says which were, for the [network]
// line a caller prints.
type HTTPRegistry struct {
	// Base is the registry root; empty is DefaultRegistry.
	Base   string
	Client *http.Client

	mu        sync.Mutex
	cache     map[string]map[string]map[string]string
	requested []string
}

// NewHTTPRegistry reads from base (empty: the public registry).
func NewHTTPRegistry(base string) *HTTPRegistry {
	return &HTTPRegistry{Base: base, Client: &http.Client{Timeout: 20 * time.Second}}
}

// Requested is every package name this registry was asked about, in order.
func (r *HTTPRegistry) Requested() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]string(nil), r.requested...)
}

// Host is the registry's host, for the [network] line.
func (r *HTTPRegistry) Host() string {
	base := r.Base
	if base == "" {
		base = DefaultRegistry
	}
	if u, err := url.Parse(base); err == nil && u.Host != "" {
		return u.Host
	}
	return base
}

// Releases fetches pkg's abbreviated document (the one npm install reads),
// which lists every release with its declared dependencies. The full document
// of a popular package runs to tens of megabytes; this one carries what is
// needed.
func (r *HTTPRegistry) Releases(ctx context.Context, pkg string) (map[string]map[string]string, error) {
	r.mu.Lock()
	if rel, ok := r.cache[pkg]; ok {
		r.mu.Unlock()
		return rel, nil
	}
	r.requested = append(r.requested, pkg)
	r.mu.Unlock()

	base := strings.TrimSuffix(r.Base, "/")
	if base == "" {
		base = DefaultRegistry
	}
	// A scoped name keeps its @ and escapes its slash, as npm sends it.
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base+"/"+strings.ReplaceAll(pkg, "/", "%2f"), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("npm registry: %w", err)
	}
	req.Header.Set("Accept", "application/vnd.npm.install-v1+json")
	req.Header.Set("User-Agent", "nox (+https://github.com/nox-hq/nox)")
	client := r.Client
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("npm registry: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	// Anything but 200 is an error: an empty answer would read as "no release
	// of this package allows the fix", which is a claim about the package.
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("npm registry returned HTTP %d for %s", resp.StatusCode, pkg)
	}
	var doc struct {
		Versions map[string]struct {
			Dependencies         map[string]string `json:"dependencies"`
			OptionalDependencies map[string]string `json:"optionalDependencies"`
		} `json:"versions"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 64<<20)).Decode(&doc); err != nil {
		return nil, fmt.Errorf("reading the npm registry's answer for %s: %w", pkg, err)
	}
	rel := make(map[string]map[string]string, len(doc.Versions))
	for v, d := range doc.Versions {
		deps := map[string]string{}
		for n, rg := range d.OptionalDependencies {
			deps[n] = rg
		}
		for n, rg := range d.Dependencies {
			deps[n] = rg
		}
		rel[v] = deps
	}
	r.mu.Lock()
	if r.cache == nil {
		r.cache = map[string]map[string]map[string]string{}
	}
	r.cache[pkg] = rel
	r.mu.Unlock()
	return rel, nil
}
