package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"github.com/nox-hq/nox/registry"
)

// InstalledPlugin records metadata for a locally installed plugin.
type InstalledPlugin struct {
	Name       string    `json:"name"`
	Version    string    `json:"version"`
	Digest     string    `json:"digest"`
	BinaryPath string    `json:"binary_path"`
	TrustLevel string    `json:"trust_level"`
	RiskClass  string    `json:"risk_class"`
	InstalledAt time.Time `json:"installed_at"`
	UpdatedAt   time.Time `json:"updated_at"`
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
func (s *State) AddPlugin(p InstalledPlugin) {
	for i := range s.Plugins {
		if s.Plugins[i].Name == p.Name {
			s.Plugins[i] = p
			return
		}
	}
	s.Plugins = append(s.Plugins, p)
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
	for i, p := range s.Plugins {
		digests[i] = p.Digest
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
