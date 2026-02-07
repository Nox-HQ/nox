package deps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
)

// parseGoSum extracts unique module/version pairs from go.sum content.
//
// Each line has the format:
//
//	module version hash
//
// A module may appear twice: once for the module source and once for the
// go.mod file (with a "/go.mod" suffix on the version). We deduplicate by
// stripping the /go.mod suffix and keeping only unique module+version pairs.
func parseGoSum(content []byte) ([]Package, error) {
	type key struct{ mod, ver string }
	seen := make(map[key]struct{})
	var pkgs []Package

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "//") {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 3 {
			continue
		}

		mod := fields[0]
		ver := fields[1]

		// Strip /go.mod suffix from version so both entries resolve to the
		// same module+version pair.
		ver = strings.TrimSuffix(ver, "/go.mod")

		k := key{mod, ver}
		if _, exists := seen[k]; exists {
			continue
		}
		seen[k] = struct{}{}

		pkgs = append(pkgs, Package{
			Name:      mod,
			Version:   ver,
			Ecosystem: "go",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning go.sum: %w", err)
	}

	return pkgs, nil
}

// packageLockJSON is the minimal structure needed to extract packages from
// npm package-lock.json v2/v3. The "packages" map is keyed by path; the root
// package uses the empty string "" as its key.
type packageLockJSON struct {
	Packages map[string]struct {
		Version string `json:"version"`
	} `json:"packages"`
}

// parsePackageLockJSON extracts dependencies from an npm package-lock.json
// v2/v3 file. The root entry (key "") is skipped because it represents the
// project itself rather than a dependency.
func parsePackageLockJSON(content []byte) ([]Package, error) {
	var lock packageLockJSON
	if err := json.Unmarshal(content, &lock); err != nil {
		return nil, fmt.Errorf("parsing package-lock.json: %w", err)
	}

	var pkgs []Package
	for path, info := range lock.Packages {
		// Skip the root package entry.
		if path == "" {
			continue
		}

		// The key is a path like "node_modules/express" or
		// "node_modules/express/node_modules/debug". Extract the package
		// name from the last node_modules/ segment.
		name := extractNpmPackageName(path)
		if name == "" || info.Version == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   info.Version,
			Ecosystem: "npm",
		})
	}

	return pkgs, nil
}

// extractNpmPackageName extracts the npm package name from a
// package-lock.json path key. Paths follow the pattern
// "node_modules/@scope/name" or "node_modules/name", potentially nested.
func extractNpmPackageName(path string) string {
	const prefix = "node_modules/"

	// Find the last occurrence of node_modules/ to handle nested deps.
	idx := strings.LastIndex(path, prefix)
	if idx == -1 {
		return ""
	}

	name := path[idx+len(prefix):]
	return name
}

// parseRequirementsTxt extracts pinned packages from a Python requirements.txt
// file. It supports the == operator for exact pinning and also extracts the
// version from >=, <=, ~=, and != specifiers (taking the version after the
// operator). Lines without a version specifier are skipped.
func parseRequirementsTxt(content []byte) ([]Package, error) {
	var pkgs []Package

	// Version specifier operators ordered from longest to shortest so that
	// two-character operators match before single-character ones.
	operators := []string{"==", ">=", "<=", "~=", "!="}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines, comments, and option lines.
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue
		}

		// Strip inline comments.
		if idx := strings.Index(line, "#"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip environment markers (e.g. ; python_version >= "3.6").
		if idx := strings.Index(line, ";"); idx != -1 {
			line = strings.TrimSpace(line[:idx])
		}

		// Strip extras (e.g. package[extra]==1.0).
		if idx := strings.Index(line, "["); idx != -1 {
			bracket := strings.Index(line, "]")
			if bracket != -1 && bracket > idx {
				line = line[:idx] + line[bracket+1:]
			}
		}

		// Try each operator to split name and version.
		var name, version string
		found := false
		for _, op := range operators {
			if idx := strings.Index(line, op); idx != -1 {
				name = strings.TrimSpace(line[:idx])
				// Take only the first version (before any comma for
				// compound specifiers like >=1.0,<2.0).
				ver := strings.TrimSpace(line[idx+len(op):])
				if comma := strings.Index(ver, ","); comma != -1 {
					ver = strings.TrimSpace(ver[:comma])
				}
				version = ver
				found = true
				break
			}
		}

		if !found || name == "" || version == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "pypi",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning requirements.txt: %w", err)
	}

	return pkgs, nil
}

// parseGemfileLock extracts gem names and versions from a Gemfile.lock file.
//
// The relevant section has the following structure:
//
//	GEM
//	  remote: https://rubygems.org/
//	  specs:
//	    actioncable (7.0.4)
//	    actionmailer (7.0.4)
//	      actionpack (= 7.0.4)
//
// We parse lines under GEM/specs that match the 4-space-indented pattern
// "    name (version)" but not the 6-space sub-dependency lines.
func parseGemfileLock(content []byte) ([]Package, error) {
	var pkgs []Package
	inGEM := false
	inSpecs := false

	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()

		// Detect section boundaries.
		trimmed := strings.TrimSpace(line)
		if trimmed == "GEM" {
			inGEM = true
			inSpecs = false
			continue
		}

		// A new top-level section resets the GEM context.
		if len(line) > 0 && line[0] != ' ' && trimmed != "" {
			inGEM = false
			inSpecs = false
			continue
		}

		if inGEM && trimmed == "specs:" {
			inSpecs = true
			continue
		}

		if !inGEM || !inSpecs {
			continue
		}

		// Gem entries are indented with exactly 4 spaces.
		// Sub-dependencies are indented with 6+ spaces.
		if !strings.HasPrefix(line, "    ") || strings.HasPrefix(line, "      ") {
			continue
		}

		entry := strings.TrimSpace(line)
		if entry == "" {
			continue
		}

		// Expected format: "name (version)"
		parenOpen := strings.Index(entry, "(")
		parenClose := strings.Index(entry, ")")
		if parenOpen == -1 || parenClose == -1 || parenClose <= parenOpen {
			continue
		}

		name := strings.TrimSpace(entry[:parenOpen])
		version := strings.TrimSpace(entry[parenOpen+1 : parenClose])

		if name == "" || version == "" {
			continue
		}

		pkgs = append(pkgs, Package{
			Name:      name,
			Version:   version,
			Ecosystem: "rubygems",
		})
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning Gemfile.lock: %w", err)
	}

	return pkgs, nil
}
