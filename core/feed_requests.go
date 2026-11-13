package core

import (
	"net/url"
	"sort"
	"sync"
)

// feedRequests collects the signed feeds a scan asked the network for.
//
// A feed request is separate from the dependency lookup: it is made for a
// project with no dependency at all, and to a URL .nox.yaml can point anywhere.
// The loaders report each request as it leaves, so a feed the cache answered is
// not listed and a request nobody answered is.
type feedRequests struct {
	mu   sync.Mutex
	urls map[string]struct{}
}

// note records one request. Credentials and query strings a configured feed URL
// may carry are dropped: the list is printed and written to reports.
func (r *feedRequests) note(raw string) {
	if r == nil {
		return
	}
	shown := raw
	if u, err := url.Parse(raw); err == nil {
		u.User, u.RawQuery, u.Fragment = nil, "", ""
		shown = u.String()
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.urls == nil {
		r.urls = make(map[string]struct{})
	}
	r.urls[shown] = struct{}{}
}

// list returns the requested feed URLs, sorted, or nil when none was requested.
func (r *feedRequests) list() []string {
	if r == nil {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if len(r.urls) == 0 {
		return nil
	}
	out := make([]string, 0, len(r.urls))
	for u := range r.urls {
		out = append(out, u)
	}
	sort.Strings(out)
	return out
}
