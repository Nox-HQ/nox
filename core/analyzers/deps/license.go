// Package deps — license detection and compliance checking.
//
// DetectLicenses enriches a PackageInventory with license information extracted
// from manifest files that live alongside the lockfiles already parsed. License
// detection is best-effort: parse failures are silently ignored so that a
// missing or malformed manifest never causes the scan to fail.
//
// CheckLicenses evaluates packages against a deny/allow license policy and
// returns findings for violations.
package deps

import (
	"bufio"
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

// DetectLicenses enriches packages in the inventory with license information
// read from manifest files in basePath. It inspects companion files for each
// ecosystem (package.json, Cargo.toml, pom.xml, etc.). Detection is best-effort;
// errors are silently ignored.
func DetectLicenses(basePath string, inventory *PackageInventory) {
	inventory.mu.Lock()
	pkgs := make([]Package, len(inventory.pkgs))
	copy(pkgs, inventory.pkgs)
	inventory.mu.Unlock()

	// Build ecosystem-specific license lookups for this directory.
	npmLicenses := detectNPMLicenses(basePath)
	cargoLicenses := detectCargoLicenses(basePath)
	mavenLicenses := detectMavenLicenses(basePath)
	pypiLicenses := detectPyPILicenses(basePath)
	goLicense := detectGoLicense(basePath)
	rubyLicenses := detectRubyLicenses(basePath)

	for i, pkg := range pkgs {
		if pkg.License != "" {
			continue
		}
		var license string
		switch pkg.Ecosystem {
		case "npm":
			license = npmLicenses[pkg.Name]
		case "cargo":
			license = cargoLicenses[pkg.Name]
		case "maven", "gradle":
			license = mavenLicenses[pkg.Name]
		case "pypi":
			license = pypiLicenses[pkg.Name]
		case "go":
			license = goLicense
		case "rubygems":
			license = rubyLicenses[pkg.Name]
		}
		if license != "" {
			inventory.SetLicense(i, license)
		}
	}
}

// CheckLicenses evaluates packages against a license policy and returns
// findings for violations. If deny is specified, any package whose license
// matches (case-insensitive prefix) any entry in deny produces a finding.
// If allow is specified, any package whose license does NOT match any entry
// in allow produces a finding. Packages without detected licenses are
// skipped to avoid false positives.
func CheckLicenses(inventory *PackageInventory, deny, allow []string) []findings.Finding {
	if len(deny) == 0 && len(allow) == 0 {
		return nil
	}

	pkgs := inventory.Packages()
	var result []findings.Finding

	for _, pkg := range pkgs {
		if pkg.License == "" {
			continue
		}

		if len(deny) > 0 && matchesLicenseList(pkg.License, deny) {
			result = append(result, findings.Finding{
				RuleID:     "LIC-001",
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceHigh,
				Location: findings.Location{
					FilePath:  "",
					StartLine: 1,
				},
				Message: fmt.Sprintf("Dependency %s@%s uses denied license %q", pkg.Name, pkg.Version, pkg.License),
				Metadata: map[string]string{
					"package":   pkg.Name,
					"version":   pkg.Version,
					"ecosystem": pkg.Ecosystem,
					"license":   pkg.License,
				},
			})
		}

		if len(allow) > 0 && !matchesLicenseList(pkg.License, allow) {
			result = append(result, findings.Finding{
				RuleID:     "LIC-001",
				Severity:   findings.SeverityHigh,
				Confidence: findings.ConfidenceHigh,
				Location: findings.Location{
					FilePath:  "",
					StartLine: 1,
				},
				Message: fmt.Sprintf("Dependency %s@%s uses license %q which is not in the allow list", pkg.Name, pkg.Version, pkg.License),
				Metadata: map[string]string{
					"package":   pkg.Name,
					"version":   pkg.Version,
					"ecosystem": pkg.Ecosystem,
					"license":   pkg.License,
				},
			})
		}
	}

	return result
}

// matchesLicenseList checks if the given license matches any entry in the list
// using case-insensitive prefix matching. For example, "GPL" matches
// "GPL-2.0", "GPL-3.0-only", etc.
func matchesLicenseList(license string, list []string) bool {
	lower := strings.ToLower(license)
	for _, entry := range list {
		entryLower := strings.ToLower(entry)
		if strings.HasPrefix(lower, entryLower) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Ecosystem-specific license detectors
// ---------------------------------------------------------------------------

// detectNPMLicenses reads package.json and node_modules/*/package.json to
// extract license information for npm packages. Returns a map of package
// name to license string.
func detectNPMLicenses(basePath string) map[string]string {
	result := make(map[string]string)
	path := filepath.Join(basePath, "package.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}

	var pkg struct {
		Name    string          `json:"name"`
		License json.RawMessage `json:"license"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return result
	}

	// The license field can be a string or an object {type: "MIT"}.
	license := extractJSONLicense(pkg.License)
	if license != "" && pkg.Name != "" {
		result[pkg.Name] = license
	}

	// Read license info from node_modules package.json files.
	nodeModules := filepath.Join(basePath, "node_modules")
	entries, err := os.ReadDir(nodeModules)
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if strings.HasPrefix(name, ".") {
			continue
		}

		// Handle scoped packages (@scope/name).
		if strings.HasPrefix(name, "@") {
			scopeDir := filepath.Join(nodeModules, name)
			scopeEntries, err := os.ReadDir(scopeDir)
			if err != nil {
				continue
			}
			for _, se := range scopeEntries {
				if !se.IsDir() {
					continue
				}
				scopedName := name + "/" + se.Name()
				lic := readNPMPackageLicense(filepath.Join(scopeDir, se.Name(), "package.json"))
				if lic != "" {
					result[scopedName] = lic
				}
			}
			continue
		}

		lic := readNPMPackageLicense(filepath.Join(nodeModules, name, "package.json"))
		if lic != "" {
			result[name] = lic
		}
	}

	return result
}

// readNPMPackageLicense reads a single node_modules package.json and extracts
// the license field.
func readNPMPackageLicense(path string) string {
	data, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	var pkg struct {
		License json.RawMessage `json:"license"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return ""
	}
	return extractJSONLicense(pkg.License)
}

// extractJSONLicense extracts a license string from a JSON value that can be
// either a string ("MIT") or an object ({"type": "MIT"}).
func extractJSONLicense(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}

	// Try string first.
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return strings.TrimSpace(s)
	}

	// Try object with "type" field.
	var obj struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(raw, &obj); err == nil && obj.Type != "" {
		return strings.TrimSpace(obj.Type)
	}

	return ""
}

// detectCargoLicenses reads Cargo.toml to extract the license field under
// [package]. Returns a map of crate name to license.
func detectCargoLicenses(basePath string) map[string]string {
	result := make(map[string]string)
	path := filepath.Join(basePath, "Cargo.toml")
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}

	name, license := parseCargoTOMLLicense(data)
	if name != "" && license != "" {
		result[name] = license
	}

	return result
}

// parseCargoTOMLLicense extracts the package name and license from a Cargo.toml
// file using line-based parsing. We avoid a full TOML parser to keep
// dependencies minimal.
func parseCargoTOMLLicense(data []byte) (name, license string) {
	inPackage := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Detect section headers.
		if strings.HasPrefix(line, "[") {
			inPackage = line == "[package]"
			continue
		}

		if !inPackage {
			continue
		}

		if strings.HasPrefix(line, "name") {
			if val := extractTOMLValue(line); val != "" {
				name = val
			}
		}
		if strings.HasPrefix(line, "license") && !strings.HasPrefix(line, "license-file") {
			if val := extractTOMLValue(line); val != "" {
				license = val
			}
		}
	}

	return name, license
}

// extractTOMLValue extracts the string value from a TOML key = "value" line.
func extractTOMLValue(line string) string {
	parts := strings.SplitN(line, "=", 2)
	if len(parts) != 2 {
		return ""
	}
	return unquoteTOML(parts[1])
}

// detectMavenLicenses reads pom.xml to extract license information from the
// <licenses> element. Returns a map of "groupId:artifactId" to license name.
func detectMavenLicenses(basePath string) map[string]string {
	result := make(map[string]string)
	path := filepath.Join(basePath, "pom.xml")
	data, err := os.ReadFile(path)
	if err != nil {
		return result
	}

	var pom struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
		Licenses   struct {
			License []struct {
				Name string `xml:"name"`
			} `xml:"license"`
		} `xml:"licenses"`
	}
	if err := xml.Unmarshal(data, &pom); err != nil {
		return result
	}

	if len(pom.Licenses.License) > 0 && pom.GroupID != "" && pom.ArtifactID != "" {
		name := pom.GroupID + ":" + pom.ArtifactID
		license := pom.Licenses.License[0].Name
		if license != "" {
			result[name] = normalizeLicenseName(license)
		}
	}

	return result
}

// detectPyPILicenses reads pyproject.toml or setup.cfg to extract license
// information. Returns a map of package name to license.
func detectPyPILicenses(basePath string) map[string]string {
	result := make(map[string]string)

	// Try pyproject.toml first.
	if name, license := parsePyprojectTOML(filepath.Join(basePath, "pyproject.toml")); name != "" && license != "" {
		result[name] = license
	}

	// Fall back to setup.cfg.
	if len(result) == 0 {
		if name, license := parseSetupCfg(filepath.Join(basePath, "setup.cfg")); name != "" && license != "" {
			result[name] = license
		}
	}

	return result
}

// parsePyprojectTOML extracts the project name and license from pyproject.toml.
func parsePyprojectTOML(path string) (name, license string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}

	inProject := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if strings.HasPrefix(line, "[") {
			inProject = line == "[project]"
			continue
		}

		if !inProject {
			continue
		}

		if strings.HasPrefix(line, "name") {
			if val := extractTOMLValue(line); val != "" {
				name = val
			}
		}
		if strings.HasPrefix(line, "license") {
			if val := extractTOMLValue(line); val != "" {
				license = val
			}
		}
	}

	return name, license
}

// parseSetupCfg extracts the package name and license from setup.cfg using
// the [metadata] section.
func parseSetupCfg(path string) (name, license string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}

	inMetadata := false

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if strings.HasPrefix(trimmed, "[") {
			inMetadata = strings.EqualFold(trimmed, "[metadata]")
			continue
		}

		if !inMetadata {
			continue
		}

		if strings.HasPrefix(trimmed, "name") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				name = strings.TrimSpace(parts[1])
			}
		}

		if strings.HasPrefix(trimmed, "license") && !strings.HasPrefix(trimmed, "license_file") {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				license = strings.TrimSpace(parts[1])
			}
		}

		// Check classifiers for license.
		if strings.HasPrefix(trimmed, "classifier") && strings.Contains(trimmed, "License") {
			// Format: classifier = License :: OSI Approved :: MIT License
			if idx := strings.Index(trimmed, "License ::"); idx != -1 {
				parts := strings.Split(trimmed[idx:], "::")
				if len(parts) >= 3 {
					lic := strings.TrimSpace(parts[2])
					lic = strings.TrimSuffix(lic, " License")
					if lic != "" && license == "" {
						license = lic
					}
				}
			}
		}
	}

	return name, license
}

// detectGoLicense looks for a LICENSE file in the module root directory and
// attempts to identify the license from its content.
func detectGoLicense(basePath string) string {
	licenseFiles := []string{
		"LICENSE", "LICENSE.md", "LICENSE.txt",
		"LICENCE", "LICENCE.md", "LICENCE.txt",
	}
	for _, name := range licenseFiles {
		path := filepath.Join(basePath, name)
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		if license := identifyLicenseFromContent(string(data)); license != "" {
			return license
		}
	}
	return ""
}

// identifyLicenseFromContent attempts to identify a license from its text
// content using simple heuristics. This is intentionally conservative to
// avoid false positives.
func identifyLicenseFromContent(content string) string {
	lower := strings.ToLower(content)

	switch {
	case strings.Contains(lower, "mit license") ||
		strings.Contains(lower, "permission is hereby granted, free of charge"):
		return "MIT"
	case strings.Contains(lower, "apache license") && strings.Contains(lower, "version 2.0"):
		return "Apache-2.0"
	case strings.Contains(lower, "gnu general public license") && strings.Contains(lower, "version 3"):
		return "GPL-3.0"
	case strings.Contains(lower, "gnu general public license") && strings.Contains(lower, "version 2"):
		return "GPL-2.0"
	case strings.Contains(lower, "gnu lesser general public license") && strings.Contains(lower, "version 3"):
		return "LGPL-3.0"
	case strings.Contains(lower, "gnu lesser general public license") && strings.Contains(lower, "version 2.1"):
		return "LGPL-2.1"
	case strings.Contains(lower, "gnu affero general public license"):
		return "AGPL-3.0"
	case strings.Contains(lower, "bsd 3-clause") ||
		(strings.Contains(lower, "redistribution and use in source and binary forms") &&
			(strings.Contains(lower, "neither the name") || strings.Contains(lower, "3. neither"))):
		return "BSD-3-Clause"
	case strings.Contains(lower, "bsd 2-clause") ||
		(strings.Contains(lower, "redistribution and use in source and binary forms") &&
			!strings.Contains(lower, "neither the name")):
		return "BSD-2-Clause"
	case strings.Contains(lower, "mozilla public license") && strings.Contains(lower, "2.0"):
		return "MPL-2.0"
	case strings.Contains(lower, "isc license"):
		return "ISC"
	case strings.Contains(lower, "the unlicense"):
		return "Unlicense"
	}

	return ""
}

// detectRubyLicenses reads .gemspec files to extract license information.
// Returns a map of gem name to license.
func detectRubyLicenses(basePath string) map[string]string {
	result := make(map[string]string)

	entries, err := os.ReadDir(basePath)
	if err != nil {
		return result
	}

	for _, entry := range entries {
		if !strings.HasSuffix(entry.Name(), ".gemspec") {
			continue
		}
		name, license := parseGemspec(filepath.Join(basePath, entry.Name()))
		if name != "" && license != "" {
			result[name] = license
		}
	}

	return result
}

// parseGemspec extracts the gem name and license from a .gemspec file using
// simple line-based pattern matching.
func parseGemspec(path string) (name, license string) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", ""
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Match: spec.name = "gemname" or s.name = "gemname"
		if strings.Contains(line, ".name") && strings.Contains(line, "=") &&
			!strings.Contains(line, "file_name") {
			if val := extractRubyStringValue(line); val != "" {
				name = val
			}
		}

		// Match: spec.license = "MIT" or spec.licenses = ["MIT"]
		if strings.Contains(line, ".license") && strings.Contains(line, "=") {
			if val := extractRubyStringValue(line); val != "" {
				license = val
			}
			// Handle array form: spec.licenses = ["MIT"]
			if license == "" && strings.Contains(line, "[") {
				start := strings.Index(line, "[")
				end := strings.Index(line, "]")
				if start != -1 && end > start {
					inner := strings.TrimSpace(line[start+1 : end])
					if val := extractRubyStringValue(inner); val != "" {
						license = val
					}
				}
			}
		}
	}

	return name, license
}

// extractRubyStringValue extracts a string value from a Ruby assignment line.
// It looks for both single and double quoted strings.
func extractRubyStringValue(line string) string {
	eqIdx := strings.Index(line, "=")
	if eqIdx == -1 {
		eqIdx = 0
	}
	rest := line[eqIdx:]

	for _, quote := range []byte{'"', '\''} {
		start := strings.IndexByte(rest, quote)
		if start == -1 {
			continue
		}
		end := strings.IndexByte(rest[start+1:], quote)
		if end == -1 {
			continue
		}
		return rest[start+1 : start+1+end]
	}

	return ""
}

// normalizeLicenseName attempts to normalize common license names to their
// SPDX identifiers.
func normalizeLicenseName(name string) string {
	lower := strings.ToLower(strings.TrimSpace(name))

	switch {
	case lower == "mit" || lower == "mit license":
		return "MIT"
	case strings.HasPrefix(lower, "apache") && strings.Contains(lower, "2"):
		return "Apache-2.0"
	case lower == "bsd-2-clause" || lower == "bsd 2-clause" || lower == "simplified bsd":
		return "BSD-2-Clause"
	case lower == "bsd-3-clause" || lower == "bsd 3-clause" || lower == "new bsd":
		return "BSD-3-Clause"
	case strings.HasPrefix(lower, "gpl") && strings.Contains(lower, "3"):
		return "GPL-3.0"
	case strings.HasPrefix(lower, "gpl") && strings.Contains(lower, "2"):
		return "GPL-2.0"
	case strings.HasPrefix(lower, "lgpl") && strings.Contains(lower, "3"):
		return "LGPL-3.0"
	case strings.HasPrefix(lower, "lgpl") && strings.Contains(lower, "2"):
		return "LGPL-2.1"
	case strings.HasPrefix(lower, "agpl"):
		return "AGPL-3.0"
	case lower == "mpl-2.0" || lower == "mozilla public license 2.0":
		return "MPL-2.0"
	case lower == "isc" || lower == "isc license":
		return "ISC"
	case lower == "unlicense" || lower == "the unlicense":
		return "Unlicense"
	}

	return strings.TrimSpace(name)
}
