package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/nox-hq/nox/registry"
	"gopkg.in/yaml.v3"
)

// runPluginEntry produces a registry index entry (JSON) for a plugin
// directory. Operators paste the output into a PR against the
// official registry repo (or their private fork) to publish the
// plugin. This sidesteps the chicken-and-egg of "plugins exist but
// no marketplace": the marketplace is a JSON file in a git repo and
// the entry generator removes the manual hand-authoring step.
//
// Inputs are read from plugin.yaml in the target directory plus
// command-line flags for version + repository. Output is JSON
// pretty-printed.
func runPluginEntry(args []string) int {
	fs := flag.NewFlagSet("plugin entry", flag.ContinueOnError)
	var (
		dir          string
		version      string
		repo         string
		owner        string
		minNox       string
		stdout       bool
		outFile      string
		stampDigests bool
	)
	fs.StringVar(&dir, "dir", ".", "path to plugin source directory containing plugin.yaml")
	fs.StringVar(&version, "release", "", "release version (e.g. 0.1.0); read from plugin.yaml when empty")
	fs.StringVar(&repo, "repo", "", "github repository slug, e.g. nox-hq/nox-plugin-foo")
	fs.StringVar(&owner, "owner", "nox-hq", "github org owning the plugin (used to derive default repo slug)")
	fs.StringVar(&minNox, "min-nox", "0.6.0", "minimum nox version this plugin requires")
	fs.BoolVar(&stdout, "stdout", true, "print to stdout (default)")
	fs.StringVar(&outFile, "output", "", "write to this file instead of stdout")
	fs.BoolVar(&stampDigests, "stamp-digests", false, "fetch checksums.txt from the release URL and replace sha256:tbd placeholders with real SHA-256s")
	if err := fs.Parse(args); err != nil {
		return 2
	}

	manifest, err := loadPluginManifest(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		return 2
	}
	if version == "" {
		version = manifest.Version
	}
	if version == "" {
		fmt.Fprintln(os.Stderr, "error: missing --version (and plugin.yaml has no version)")
		return 2
	}
	if repo == "" {
		// Derive repo slug from the manifest name. Handle both
		// `nox/foo` and `nox-plugin-foo` shapes; either way we want
		// `owner/nox-plugin-foo`.
		shortName := strings.TrimPrefix(manifest.Name, "nox/")
		shortName = strings.TrimPrefix(shortName, "nox-plugin-")
		repo = owner + "/nox-plugin-" + shortName
	}

	entry := buildPluginEntry(manifest, version, repo, minNox)

	if stampDigests {
		if err := stampEntryDigests(&entry, repo, version); err != nil {
			fmt.Fprintf(os.Stderr, "error: stamping digests: %v\n", err)
			return 2
		}
	}

	out, err := json.MarshalIndent(entry, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: marshalling entry: %v\n", err)
		return 2
	}

	if outFile != "" {
		if err := os.WriteFile(outFile, out, 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "error: writing %s: %v\n", outFile, err)
			return 2
		}
		fmt.Fprintf(os.Stderr, "[plugin entry] wrote %s\n", outFile)
		return 0
	}

	fmt.Println(string(out))
	return 0
}

// pluginManifest mirrors the on-disk plugin.yaml shape. Loose typing
// here so unknown fields don't reject the file — operators may add
// future schema fields the entry generator doesn't yet read.
type pluginManifest struct {
	Name        string `yaml:"name"`
	Version     string `yaml:"version"`
	Track       string `yaml:"track"`
	Description string `yaml:"description"`
	Tools       []struct {
		Name        string `yaml:"name"`
		Description string `yaml:"description"`
	} `yaml:"tools"`
}

func loadPluginManifest(dir string) (*pluginManifest, error) {
	data, err := os.ReadFile(filepath.Join(dir, "plugin.yaml"))
	if err != nil {
		return nil, fmt.Errorf("reading plugin.yaml: %w", err)
	}
	var m pluginManifest
	if err := yaml.Unmarshal(data, &m); err != nil {
		return nil, fmt.Errorf("parsing plugin.yaml: %w", err)
	}
	return &m, nil
}

func buildPluginEntry(m *pluginManifest, version, repo, minNox string) registry.PluginEntry {
	noxName := m.Name
	if !strings.HasPrefix(noxName, "nox/") {
		noxName = "nox/" + strings.TrimPrefix(noxName, "nox-plugin-")
	}
	repoURL := "https://github.com/" + repo
	binBase := strings.TrimPrefix(noxName, "nox/")
	binBase = "nox-plugin-" + binBase

	caps := make([]string, 0, len(m.Tools))
	for _, t := range m.Tools {
		caps = append(caps, t.Name)
	}

	artifacts := make([]registry.PlatformArtifact, 0, 6)
	for _, p := range []struct{ os, arch string }{
		{"linux", "amd64"},
		{"linux", "arm64"},
		{"darwin", "amd64"},
		{"darwin", "arm64"},
		{"windows", "amd64"},
	} {
		ext := "tar.gz"
		if p.os == "windows" {
			ext = "zip"
		}
		url := fmt.Sprintf("%s/releases/download/v%s/%s_%s_%s_%s.%s",
			repoURL, version, binBase, version, p.os, p.arch, ext)
		artifacts = append(artifacts, registry.PlatformArtifact{
			OS:     p.os,
			Arch:   p.arch,
			URL:    url,
			Digest: "sha256:tbd",
			// Cosign keyless signs checksums.txt. The plugin release
			// workflows run cosign v4, which writes a single
			// checksums.txt.sigstore.json and NO detached .sig — the v3
			// pair (.sig + .sig.bundle) is not published at all.
			//
			// Emitting the v3 names produced entries pointing at files that
			// were never uploaded: the signature download 404s, the artifact
			// is classified "unverified", and the install is blocked by the
			// default trust policy. Every plugin version published after the
			// move to cosign v4 was uninstallable until the index was
			// repaired by hand. CosignSigURL is left empty (omitempty drops
			// it) because v4 has nothing to put there.
			CosignBundleURL: fmt.Sprintf("%s/releases/download/v%s/checksums.txt.sigstore.json", repoURL, version),
			// Case-insensitive prefix: GitHub preserves the org's
			// canonical case in OIDC certificate SANs (e.g. "Nox-HQ"),
			// but the registry index conventionally lowercases owners.
			// `(?i)` makes the comparison robust to either casing.
			CosignCertIdentityRegexp: fmt.Sprintf("(?i)https://github.com/%s/.github/workflows/release.yml@.*", repo),
			CosignOIDCIssuer:         "https://token.actions.githubusercontent.com",
		})
	}

	return registry.PluginEntry{
		Name:        noxName,
		Description: m.Description,
		Homepage:    repoURL,
		Repository:  repoURL,
		License:     "Apache-2.0",
		Track:       registry.Track(m.Track),
		Maintainers: []string{"nox-hq"},
		Versions: []registry.VersionEntry{{
			Version:       version,
			APIVersion:    "v1",
			PublishedAt:   time.Now().UTC(),
			Digest:        "sha256:tbd",
			Capabilities:  caps,
			MinNoxVersion: minNox,
			ChangelogURL:  repoURL + "/blob/main/CHANGELOG.md",
			Artifacts:     artifacts,
		}},
	}
}

// stampEntryDigests downloads the GoReleaser-published checksums.txt
// for the release tag and rewrites every sha256:tbd placeholder in
// the entry's artifacts with the real SHA-256. Plugin release
// pipelines call this at the end of the workflow before opening the
// PR against the marketplace registry — the entry shipped to nox-hq/nox
// then carries enforceable digests instead of placeholders.
func stampEntryDigests(entry *registry.PluginEntry, repo, version string) error {
	checksumURL := fmt.Sprintf("https://github.com/%s/releases/download/v%s/checksums.txt", repo, version)
	body, err := fetchHTTP(checksumURL)
	if err != nil {
		return fmt.Errorf("fetching %s: %w", checksumURL, err)
	}
	digests := parseChecksumsFile(body)
	if len(digests) == 0 {
		return fmt.Errorf("no SHA-256 entries parsed from %s", checksumURL)
	}

	stamped := 0
	for vi := range entry.Versions {
		ve := &entry.Versions[vi]
		for ai := range ve.Artifacts {
			a := &ve.Artifacts[ai]
			fname := filepath.Base(a.URL)
			if d, ok := digests[fname]; ok {
				a.Digest = "sha256:" + d
				stamped++
			}
		}
	}
	if stamped == 0 {
		return fmt.Errorf("checksums.txt at %s did not match any artifact filename", checksumURL)
	}
	fmt.Fprintf(os.Stderr, "[plugin entry] stamped %d digests from %s\n", stamped, checksumURL)
	return nil
}

// fetchHTTP retrieves a small text file (e.g. checksums.txt) and
// returns its body. Caps the read at 1 MB so a hostile redirect
// can't exhaust memory.
func fetchHTTP(url string) ([]byte, error) {
	resp, err := stdHTTPGet(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close() //nolint:errcheck // best-effort
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, 1<<20))
}

// stdHTTPGet is a tiny wrapper so tests can override.
//
// the closure exists both so tests can substitute it and to carry the
// gosec/noctx suppression below, which has nowhere to live on a bare reference.
//
//nolint:gocritic // unlambda: NOT replaceable with a bare http.Get reference —
var stdHTTPGet = func(url string) (*http.Response, error) {
	return http.Get(url) //nolint:gosec,noctx // checksum URL is operator-supplied; install path validates contents
}

// parseChecksumsFile parses a GoReleaser-style checksums.txt:
//
//	<hex-sha256>  <filename>
//
// One line per artifact. Returns a map of filename -> hex digest.
func parseChecksumsFile(body []byte) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(string(body), "\n") {
		fields := strings.Fields(line)
		if len(fields) != 2 {
			continue
		}
		hex := fields[0]
		name := fields[1]
		if len(hex) < 32 {
			continue
		}
		out[name] = hex
	}
	return out
}
