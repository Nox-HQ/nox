package deps

import (
	"bytes"
	"strings"
)

// Parsers for lockfile formats that nox classified but could not read. Until
// these existed, a yarn, pnpm or poetry project produced an empty dependency
// inventory and no vulnerability findings at all.
//
// All three are hand-written rather than YAML/TOML-decoded, deliberately: the
// formats are only superficially YAML/TOML, versions differ in schema, and a
// strict decoder rejects the whole file over one unexpected key — turning a
// partial read into a total blind spot. These extract the two fields that
// matter (name, resolved version) and skip what they do not recognise.
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

// parsePnpmLock extracts packages from a pnpm lockfile.
//
// Entries live under `packages:` keyed by path. Lockfile v6 and later write
// "/name@version"; v5 and earlier write "/name/version". Both forms are in the
// wild, and a scoped package contains a '/' in its own name, so the separator
// has to be located from the right rather than split naively.
func parsePnpmLock(content []byte) ([]Package, error) {
	var pkgs []Package

	inPackages := false
	scanner := newLineScanner(bytes.NewReader(content))

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		// Top-level keys delimit sections. Only `packages:` is read: v9 also
		// has a `snapshots:` section keyed identically, which would double
		// every dependency, and `importers:` lists workspace members.
		if !strings.HasPrefix(line, " ") {
			inPackages = strings.HasPrefix(trimmed, "packages:")
			continue
		}
		if !inPackages {
			continue
		}

		// Package keys are indented and end in ':'. Lockfile v5 and v6 prefix
		// them with '/'; v9 — the default since 2024 — dropped the slash, so
		// requiring it silently yielded zero packages for most current pnpm
		// projects.
		if !strings.HasSuffix(trimmed, ":") {
			continue
		}

		key := strings.TrimSuffix(trimmed, ":")
		key = strings.Trim(key, `'"`)
		key = strings.TrimPrefix(key, "/")

		// Ignore nested keys such as `resolution:` and `peerDependencies:`,
		// which are indented further and carry no version.
		if !strings.Contains(key, "@") && !strings.Contains(key, "/") {
			continue
		}

		key = stripPnpmPeerSuffix(key)

		name, version := splitPnpmKey(key)
		if name == "" || version == "" {
			continue
		}
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "npm"})
	}

	return pkgs, nil
}

// stripPnpmPeerSuffix removes the peer-dependency qualifier pnpm appends to a
// package key. v6+ writes "(react@18.2.0)"; v5 wrote "_react@16.8.0". Leaving
// either attached corrupts both name and version, so no advisory can match.
func stripPnpmPeerSuffix(key string) string {
	if idx := strings.Index(key, "("); idx > 0 {
		key = key[:idx]
	}
	if idx := strings.Index(key, "_"); idx > 0 {
		// Only a peer qualifier, not a legitimate underscore in a package
		// name: the qualifier always carries an '@' after the underscore.
		if strings.Contains(key[idx:], "@") {
			key = key[:idx]
		}
	}
	return key
}

// splitPnpmKey separates a pnpm package key into name and version, accepting
// both the "name@version" (v6+/v9) and "name/version" (v5) spellings.
//
// The v5 form is tried FIRST when the key has no '@' after the scope, because
// "@scope/pkg/1.0.0" contains an '@' at index 0 that must not be treated as the
// version separator.
func splitPnpmKey(key string) (name, version string) {
	// v6+/v9: "name@version", where a leading '@' is the scope marker.
	if idx := strings.LastIndex(key, "@"); idx > 0 {
		return key[:idx], key[idx+1:]
	}
	// v5: the version is the final path segment.
	if idx := strings.LastIndex(key, "/"); idx > 0 {
		return key[:idx], key[idx+1:]
	}
	return "", ""
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
