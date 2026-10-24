package deps

import (
	"bytes"
	"strings"
)

// Parsers for lockfile formats that nox classified but could not read. Until
// these existed, a yarn, pnpm or poetry project produced an empty dependency
// inventory and no vulnerability findings at all. pnpm's lives in
// parsers_pnpm.go.
//
// These two are hand-written rather than decoded: yarn v1 is not YAML at all,
// and both extract the two fields that matter (name, resolved version) while
// skipping what they do not recognise. pnpm-lock.yaml is different — it is
// real YAML whose package entries hold nested mappings keyed by package names,
// which a line scanner cannot tell from packages — so it is decoded.
//
// None of them returns an error for unrecognised content. A file that yields no
// packages is reported as a degradation by the caller, which is more useful
// than aborting a scan over one unreadable lockfile.

// maxLockfileLine bounds a single scanned line. bufio.Scanner's 64 KiB default
// is exceeded by real lockfiles — pnpm peer-dependency keys and yarn integrity
// hashes both run long — and the scanner stops silently at that limit, which
// would truncate the dependency list without any error.
const maxLockfileLine = 1024 * 1024

// parseYarnLock extracts packages from a yarn lockfile, both the v1 custom
// format and the berry (v2+) YAML-ish format.
//
// Both share the shape that matters: a descriptor line ending in ':' followed
// by an indented `version` line. The descriptor carries RANGES
// ("lodash@^4.17.0, lodash@^4.17.15"), never the resolved version, so the
// version line is the only authoritative source — reading the descriptor would
// yield "^4.17.0", which matches no advisory and silently fails every lookup.
func parseYarnLock(content []byte) ([]Package, error) {
	var pkgs []Package

	var pendingNames []string
	scanner := newLineScanner(bytes.NewReader(content))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Descriptor lines start at column 0 and end in ':'.
		if !strings.HasPrefix(line, " ") && strings.HasSuffix(trimmed, ":") {
			pendingNames = yarnDescriptorNames(strings.TrimSuffix(trimmed, ":"))
			continue
		}

		// Indented `version "1.2.3"` (v1) or `version: 1.2.3` (berry).
		if len(pendingNames) > 0 && strings.HasPrefix(line, " ") {
			key, value, found := strings.Cut(trimmed, " ")
			if !found {
				key, value, found = strings.Cut(trimmed, ":")
			}
			if found && strings.TrimSuffix(strings.TrimSpace(key), ":") == "version" {
				version := strings.Trim(strings.TrimSpace(value), `"'`)
				if version != "" {
					for _, name := range pendingNames {
						pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "npm"})
					}
				}
				pendingNames = nil
			}
		}
	}

	return pkgs, nil
}

// yarnDescriptorNames extracts package names from a yarn descriptor line, which
// may list several comma-separated ranges for the same package and quote them.
//
// Handles scoped packages, whose name itself contains the '@' that separates
// name from range: "@babel/core@^7.0.0" is the package "@babel/core".
func yarnDescriptorNames(descriptor string) []string {
	seen := make(map[string]bool)
	var names []string

	for _, part := range strings.Split(descriptor, ",") {
		spec := strings.Trim(strings.TrimSpace(part), `"'`)
		if spec == "" || strings.HasPrefix(spec, "__") {
			// __metadata and friends are berry bookkeeping, not packages.
			continue
		}

		name := yarnSpecName(spec)
		if name == "" || seen[name] {
			continue
		}
		seen[name] = true
		names = append(names, name)
	}

	return names
}

// yarnSpecName extracts the package name from a single yarn descriptor spec.
//
// The separator is the FIRST '@' after any scope prefix, not the last. Ranges
// routinely contain their own '@':
//
//	string-width-cjs@npm:string-width@^4.2.0   → string-width-cjs
//	lodash@patch:lodash@npm%3A4.17.21#...      → lodash
//	@foo/bar@npm:@baz/qux@^1.0.0               → @foo/bar
//
// Splitting on the last '@' pulls part of the range into the name, and the
// npm-alias form appears in essentially every modern berry lockfile via cliui
// and wrap-ansi. Returns "" for a fragment carrying no '@' at all, which is a
// comma that appeared INSIDE one range ("foo@>=1.0.0, <2.0.0") rather than
// between two — treating it as a package invents one that does not exist.
func yarnSpecName(spec string) string {
	// A scope's leading '@' is part of the name, so start the search past it.
	start := 0
	if strings.HasPrefix(spec, "@") {
		start = 1
	}

	idx := strings.Index(spec[start:], "@")
	if idx < 0 {
		return ""
	}
	return strings.TrimSpace(spec[:start+idx])
}

// parsePoetryLock extracts packages from a poetry lockfile.
//
// Packages are [[package]] array-of-table entries with `name` and `version`
// keys. The trap is that [package.dependencies] and [metadata] tables sit
// between entries and carry their own `version`-shaped keys — [metadata]'s
// lock-version in particular — so key extraction has to be scoped to the
// current [[package]] block rather than applied to every assignment in the file.
func parsePoetryLock(content []byte) ([]Package, error) {
	var pkgs []Package

	var name, version string
	inPackage := false

	flush := func() {
		if inPackage && name != "" && version != "" {
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "pypi"})
		}
		name, version = "", ""
	}

	scanner := newLineScanner(bytes.NewReader(content))

	for scanner.Scan() {
		trimmed := strings.TrimSpace(scanner.Text())

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "[") {
			// Any table header ends the previous package block. Only
			// [[package]] starts a new one; nested tables such as
			// [package.dependencies] and unrelated ones such as [metadata]
			// leave us outside a package so their keys are ignored.
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
		value = strings.Trim(strings.TrimSpace(value), `"'`)
		switch strings.TrimSpace(key) {
		case "name":
			name = value
		case "version":
			version = value
		}
	}
	flush()

	return pkgs, nil
}
