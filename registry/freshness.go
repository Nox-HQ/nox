package registry

import (
	"context"
	"strings"
	"time"
)

// DefaultIndexMaxAge is how old a registry index may be before nox says so. An
// index older than this has probably stopped being published, and "no newer
// version" read from it means nothing.
const DefaultIndexMaxAge = 14 * 24 * time.Hour

// HighestVersion returns the highest semantic version a plugin lists, which is
// what "latest" must mean. The last entry in the list is only the latest if the
// publisher happened to append in order. "" when no listed version parses.
func HighestVersion(p *PluginEntry) string {
	best, bestRaw := Version{}, ""
	for i := range p.Versions {
		raw := p.Versions[i].Version
		v, err := ParseVersion(strings.TrimPrefix(raw, "v"))
		if err != nil {
			continue
		}
		if bestRaw == "" || v.Compare(best) > 0 {
			best, bestRaw = v, raw
		}
	}
	return bestRaw
}

// InstalledIsNewerThanIndex reports whether the installed version is higher
// than every version the index lists: the index is behind what is running, so
// its "latest" is not the project's latest. False when either side does not
// parse; a claim about versions needs both.
func InstalledIsNewerThanIndex(installed string, p *PluginEntry) bool {
	hi := HighestVersion(p)
	if hi == "" || installed == "" {
		return false
	}
	iv, err := ParseVersion(strings.TrimPrefix(installed, "v"))
	if err != nil {
		return false
	}
	hv, err := ParseVersion(strings.TrimPrefix(hi, "v"))
	if err != nil {
		return false
	}
	return iv.Compare(hv) > 0
}

// IndexIsStale reports whether an index generated at generatedAt is older than
// maxAge at now. A zero generatedAt (the field absent) is not stale: nothing is
// known, and the caller says nothing rather than something false.
func IndexIsStale(generatedAt, now time.Time, maxAge time.Duration) bool {
	if generatedAt.IsZero() {
		return false
	}
	return now.Sub(generatedAt) > maxAge
}

// OldestGeneratedAt returns the generated_at of the oldest index among the
// configured sources, so one fresh source cannot hide a stale one. ok is false
// when no index states a time.
func (c *Client) OldestGeneratedAt(ctx context.Context) (oldest time.Time, ok bool) {
	indexes, err := c.loadAll(ctx)
	if err != nil {
		return time.Time{}, false
	}
	for _, idx := range indexes {
		if idx.GeneratedAt.IsZero() {
			continue
		}
		if !ok || idx.GeneratedAt.Before(oldest) {
			oldest, ok = idx.GeneratedAt, true
		}
	}
	return oldest, ok
}
