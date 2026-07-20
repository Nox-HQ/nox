package main

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/nox-hq/nox/registry"
	"github.com/nox-hq/nox/registry/trust"
)

// InstalledPlugin records metadata for a locally installed plugin.
type InstalledPlugin struct {
	Name       string `json:"name"`
	Version    string `json:"version"`
	Digest     string `json:"digest"`
	BinaryPath string `json:"binary_path"`
	TrustLevel string `json:"trust_level"`
	RiskClass  string `json:"risk_class"`

	// Track is the registry track this plugin was published under, captured at
	// install time. It selects the safety profile enforced at scan time, so it
	// is deliberately recorded from the registry entry and never read from the
	// plugin itself — a self-declared track would let a plugin choose its own
	// sandbox. Empty for sideloaded (--local) plugins and for installs
	// predating this field, both of which fall back to the strict default
	// policy.
	Track string `json:"track,omitempty"`

	// BinaryDigest is the SHA-256 of the plugin executable itself, measured at
	// install time. It is distinct from Digest: Digest is the signed *artifact*
	// blob, which for a tar.gz plugin is the tarball, not the extracted
	// executable — so it cannot be re-checked against the file the host execs.
	// BinaryDigest measures exactly that file. The scan path re-checks it before
	// launch and refuses to run a plugin whose binary changed since install,
	// closing the gap where a plugin, having run once, overwrites its own
	// on-disk binary to execute modified code as a still-"trusted" plugin on the
	// next scan. Empty for installs predating this field and when the hash could
	// not be read; the scan path then skips the check (unchanged behavior).
	BinaryDigest string `json:"binary_digest,omitempty"`

	InstalledAt time.Time `json:"installed_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// fileDigest returns the "sha256:<hex>" digest of the file at path.
func fileDigest(path string) (string, error) {
	f, err := os.Open(path) //nolint:gosec // path is an installed plugin binary recorded by nox
	if err != nil {
		return "", err
	}
	defer func() { _ = f.Close() }()
	d, err := trust.ComputeDigestReader(f)
	if err != nil {
		return "", err
	}
	return d.String(), nil
}

// RecordBinaryDigest measures the executable at p.BinaryPath and stores it in
// BinaryDigest. It must be called at install time, when the binary is
// known-good. A hash failure leaves the field empty rather than aborting the
// install: the scan path then falls back to no integrity check, which is no
// worse than the pre-existing behavior.
func (p *InstalledPlugin) RecordBinaryDigest() {
	if p.BinaryPath == "" {
		return
	}
	if d, err := fileDigest(p.BinaryPath); err == nil {
		p.BinaryDigest = d
	}
}

// State persists registry sources and installed plugins across CLI invocations.
type State struct {
	Sources []registry.Source `json:"sources"`
	Plugins []InstalledPlugin `json:"plugins"`
}

// FindPlugin returns the installed plugin with the given name, or nil.
func (s *State) FindPlugin(name string) *InstalledPlugin {
	for i := range s.Plugins {
		if s.Plugins[i].Name == name {
			return &s.Plugins[i]
		}
	}
	return nil
}

// AddPlugin adds or updates an installed plugin by name.
func (s *State) AddPlugin(p *InstalledPlugin) {
	for i := range s.Plugins {
		if s.Plugins[i].Name == p.Name {
			s.Plugins[i] = *p
			return
		}
	}
	s.Plugins = append(s.Plugins, *p)
}

// RemovePlugin removes an installed plugin by name. Returns true if found.
func (s *State) RemovePlugin(name string) bool {
	for i := range s.Plugins {
		if s.Plugins[i].Name == name {
			s.Plugins = append(s.Plugins[:i], s.Plugins[i+1:]...)
			return true
		}
	}
	return false
}

// InstalledDigests returns the digests of all installed plugins.
func (s *State) InstalledDigests() []string {
	digests := make([]string, len(s.Plugins))
	for i := range s.Plugins {
		digests[i] = s.Plugins[i].Digest
	}
	return digests
}

// LoadState reads state from the given path. Returns a zero State if the file
// does not exist.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return &State{}, nil
		}
		return nil, err
	}

	var st State
	if err := json.Unmarshal(data, &st); err != nil {
		return nil, err
	}
	return &st, nil
}

// SaveState writes state to path atomically (temp file + rename).
func SaveState(path string, s *State) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o644); err != nil {
		return err
	}

	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// DefaultStatePath returns the default state file path, respecting NOX_HOME.
func DefaultStatePath() string {
	return filepath.Join(noxHome(), "state.json")
}

// noxHome returns the nox home directory, respecting NOX_HOME.
func noxHome() string {
	if h := os.Getenv("NOX_HOME"); h != "" {
		return h
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".nox")
}

// trackForPlugin looks up the registry track a plugin is published under.
//
// The track selects which safety profile the host enforces, so it must come
// from the registry — the operator-configured source of truth — and never from
// the plugin's own manifest, which carries no track field for exactly this
// reason. A lookup failure returns an empty track, which the host treats as
// "provenance unknown" and falls back to the strict default policy.
func trackForPlugin(ctx context.Context, client *registry.Client, name string) registry.Track {
	entries, err := client.Search(ctx, name)
	if err != nil {
		return ""
	}
	for i := range entries {
		if entries[i].Name == name {
			return entries[i].Track
		}
	}
	return ""
}
