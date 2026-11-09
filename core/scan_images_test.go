package core

import (
	"testing"

	"github.com/nox-hq/nox/core/image"
)

// Image reading is on unless a project turns it off, and a scan that makes no
// lookups reads images from the cache only: the default must not add a
// download the user turned lookups off to avoid.
func TestImageReaderDefaultsAndOfflineness(t *testing.T) {
	off := false
	deps := ScanOptions{} // the zero ScopeSet is every scope
	cases := []struct {
		name        string
		cfg         ImagesConfig
		opts        ScanOptions
		lookups     bool
		wantReader  bool
		wantOffline bool
	}{
		{"unset is on", ImagesConfig{}, deps, true, true, false},
		{"enabled: false is off", ImagesConfig{Enabled: &off}, deps, true, false, false},
		{"no lookups reads the cache only", ImagesConfig{}, deps, false, true, true},
		{"--offline reads the cache only", ImagesConfig{}, ScanOptions{Scopes: deps.Scopes, Offline: true}, true, true, true},
		{"no deps scope, no reader", ImagesConfig{}, ScanOptions{Scopes: ScopeSet{only: map[Scope]bool{ScopeSecrets: true}}}, true, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := imageReader(c.cfg, c.opts, c.lookups)
			if (r != nil) != c.wantReader {
				t.Fatalf("reader %v, want %v", r != nil, c.wantReader)
			}
			if r != nil && r.(*image.Client).Offline != c.wantOffline {
				t.Errorf("offline %v, want %v", r.(*image.Client).Offline, c.wantOffline)
			}
		})
	}
}
