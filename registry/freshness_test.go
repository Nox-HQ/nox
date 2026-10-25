package registry

import (
	"testing"
	"time"
)

func entry(vs ...string) *PluginEntry {
	p := &PluginEntry{Name: "nox/x"}
	for _, v := range vs {
		p.Versions = append(p.Versions, VersionEntry{Version: v})
	}
	return p
}

// "Latest" is the highest version, not the last one listed.
func TestHighestVersionIsNotTheLastListed(t *testing.T) {
	if got := HighestVersion(entry("1.2.0", "1.10.0", "1.9.0")); got != "1.10.0" {
		t.Errorf("HighestVersion = %q, want 1.10.0", got)
	}
	if got := HighestVersion(entry("1.0.0-beta.1", "1.0.0")); got != "1.0.0" {
		t.Errorf("a release outranks its prerelease; got %q", got)
	}
	if got := HighestVersion(entry("not-a-version")); got != "" {
		t.Errorf("an unparseable list has no highest version; got %q", got)
	}
}

func TestInstalledIsNewerThanIndex(t *testing.T) {
	cases := []struct {
		installed string
		want      bool
	}{
		{"1.3.0", true}, {"v1.3.0", true}, {"1.2.0", false}, {"1.1.0", false}, {"", false}, {"junk", false},
	}
	for _, c := range cases {
		if got := InstalledIsNewerThanIndex(c.installed, entry("1.0.0", "1.2.0")); got != c.want {
			t.Errorf("installed %q: got %v, want %v", c.installed, got, c.want)
		}
	}
	if InstalledIsNewerThanIndex("1.0.0", entry()) {
		t.Error("an index listing no versions says nothing about the installed one")
	}
}

func TestIndexIsStale(t *testing.T) {
	now := time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC)
	if !IndexIsStale(now.Add(-15*24*time.Hour), now, DefaultIndexMaxAge) {
		t.Error("15 days old is over a 14-day limit")
	}
	if IndexIsStale(now.Add(-13*24*time.Hour), now, DefaultIndexMaxAge) {
		t.Error("13 days old is within a 14-day limit")
	}
	if IndexIsStale(time.Time{}, now, DefaultIndexMaxAge) {
		t.Error("an index that states no time is not called stale; nothing is known")
	}
}
