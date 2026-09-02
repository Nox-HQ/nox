package deps

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// The three parsers here were missing for a long time while nox scanned the
// languages they belong to. The release E2E measured it: a Pipfile.lock with
// 110 packages produced zero components and zero advisories, and nothing said
// why, because an unrecognised lockfile is not a degradation — it is simply
// not a lockfile. Each parser keeps to the same contract as its siblings:
// name, exact version, ecosystem; anything unpinned or not from a registry is
// skipped rather than guessed.

// pipfileLock is the subset of Pipfile.lock nox reads. Packages live under
// "default" and "develop"; a registry dependency carries "version": "==x.y",
// a VCS dependency carries "ref" and no version.
type pipfileLock struct {
	Default map[string]pipfileLockEntry `json:"default"`
	Develop map[string]pipfileLockEntry `json:"develop"`
}

type pipfileLockEntry struct {
	Version string `json:"version"`
}

// parsePipfileLock extracts pinned packages from a Pipfile.lock (pipenv).
func parsePipfileLock(content []byte) ([]Package, error) {
	var lock pipfileLock
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parsing Pipfile.lock: %w", err)
	}

	var pkgs []Package
	for _, section := range []map[string]pipfileLockEntry{lock.Default, lock.Develop} {
		for name, entry := range section {
			version := strings.TrimPrefix(strings.TrimSpace(entry.Version), "==")
			if name == "" || version == "" {
				continue
			}
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "pypi"})
		}
	}
	return pkgs, nil
}

// parseUvLock extracts packages from a uv.lock. The file is TOML with one
// [[package]] table per resolved package, like poetry.lock, plus a `source`
// table: a registry package resolves from an index, while the project itself
// is `source = { editable = "." }` or `{ virtual = "." }` and is not a
// dependency to look up.
func parseUvLock(content []byte) ([]Package, error) {
	var pkgs []Package

	var name, version string
	inPackage, local := false, false

	flush := func() {
		if inPackage && !local && name != "" && version != "" {
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "pypi"})
		}
		name, version, local = "", "", false
	}

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "[") {
			flush()
			inPackage = trimmed == "[[package]]"
			continue
		}
		if !inPackage {
			continue
		}
		key, value, found := strings.Cut(trimmed, "=")
		if !found {
			continue
		}
		value = strings.TrimSpace(value)
		switch strings.TrimSpace(key) {
		case "name":
			name = strings.Trim(value, `"'`)
		case "version":
			version = strings.Trim(value, `"'`)
		case "source":
			local = strings.Contains(value, "editable") || strings.Contains(value, "virtual") ||
				strings.Contains(value, "directory") || strings.Contains(value, "path")
		}
	}
	flush()

	return pkgs, nil
}

// parsePubspecLock extracts hosted packages from a Dart/Flutter pubspec.lock.
// Under `packages:` each package is a two-space-indented key whose block
// carries `source:` and `version:`; only `source: hosted` packages come from a
// registry OSV knows about (path, git and sdk sources are skipped).
func parsePubspecLock(content []byte) ([]Package, error) {
	var pkgs []Package

	var name, version, source string
	inPackages := false

	flush := func() {
		if name != "" && version != "" && source == "hosted" {
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "pub"})
		}
		name, version, source = "", "", ""
	}

	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		indent := len(line) - len(strings.TrimLeft(line, " "))
		switch {
		case indent == 0:
			flush()
			inPackages = trimmed == "packages:"
		case !inPackages:
			continue
		case indent == 2 && strings.HasSuffix(trimmed, ":"):
			flush()
			name = strings.TrimSuffix(trimmed, ":")
		case indent == 4:
			key, value, found := strings.Cut(trimmed, ":")
			if !found {
				continue
			}
			value = strings.Trim(strings.TrimSpace(value), `"'`)
			switch key {
			case "version":
				version = value
			case "source":
				source = value
			}
		}
	}
	flush()

	return pkgs, nil
}
