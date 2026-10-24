package deps

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// parsePnpmLock extracts packages from a pnpm-lock.yaml.
//
// Packages are the keys of the top-level `packages:` mapping, and nothing else
// in the file. pnpm's lockfile spec (github.com/pnpm/spec, lockfile/) defines
// three key layouts:
//
//	5.x  /name/version, with "_peer@x+peer2@y" or "_<hash>" peer suffixes (5.2.md)
//	6.0  /name@version, with "(peer@x)" peer suffixes (6.0.md)
//	9.0  name@version, no slash, no suffix; peer variants move to `snapshots:` (9.0.md)
//
// In every layout the value is a mapping of FIELDS — resolution, engines,
// dependencies, peerDependencies, peerDependenciesMeta, optionalDependencies.
// peerDependenciesMeta is keyed by package names ('@angular/core':) whose values
// are mappings, so a line scanner that accepts "any indented key containing '@'
// or '/'" reads them as packages: "@angular" at version "core". The file is
// YAML written by a YAML serialiser, so it is read with one; only the entries
// of `packages:` are visited.
//
// `snapshots:` (v9) repeats every package once per peer combination, and
// `importers:` lists each workspace member's direct dependencies; both refer to
// entries of `packages:` and add none.
//
// A file can hold more than one YAML document: when pnpm manages its own
// version it writes a document locking pnpm itself, then `---` and the
// project's lockfile. Every document is read.
//
// v5 and v6 list a package once per peer combination; it is reported once.
//
// Invalid YAML is an error rather than an empty result. The caller reports it
// as a degradation naming the file, so the operator learns these dependencies
// were not scanned instead of reading a partial inventory as a whole one.
func parsePnpmLock(content []byte) ([]Package, error) {
	type pkgKey struct{ name, version string }
	seen := make(map[pkgKey]bool)
	var pkgs []Package

	dec := yaml.NewDecoder(bytes.NewReader(content))
	for {
		var doc yaml.Node
		err := dec.Decode(&doc)
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("parsing pnpm-lock.yaml: %w", err)
		}

		root := yamlDocumentMapping(&doc)
		if root == nil {
			continue
		}
		major := pnpmLockfileMajor(yamlMappingValue(root, "lockfileVersion"))
		packages := yamlMappingValue(root, "packages")
		if packages == nil || packages.Kind != yaml.MappingNode {
			continue
		}

		for i := 0; i+1 < len(packages.Content); i += 2 {
			name, version := pnpmPackage(packages.Content[i].Value, packages.Content[i+1], major)
			k := pkgKey{name, version}
			if name == "" || version == "" || seen[k] {
				continue
			}
			seen[k] = true
			pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "npm"})
		}
	}

	return pkgs, nil
}

// pnpmPackage resolves one `packages:` entry to a name and version.
//
// The spec makes `name` and `version` fields present exactly when the key does
// not carry them — git and tarball dependencies, keyed by URL
// ("solady@git+https://...#<sha>" with `version: 0.0.237`) — so a field
// overrides what the key yields. Without that, the version is the URL, which
// matches no advisory.
func pnpmPackage(key string, entry *yaml.Node, major int) (name, version string) {
	name, version = splitPnpmPackageKey(key, major)
	if entry.Kind == yaml.MappingNode {
		if n := yamlMappingValue(entry, "name"); n != nil && n.Kind == yaml.ScalarNode && n.Value != "" {
			name = n.Value
		}
		if v := yamlMappingValue(entry, "version"); v != nil && v.Kind == yaml.ScalarNode && v.Value != "" {
			version = v.Value
		}
	}
	return name, version
}

// splitPnpmPackageKey parses a `packages:` key into name and version for the
// given lockfile major version. A major of 0 means the file did not say; the
// key's own shape decides then.
func splitPnpmPackageKey(key string, major int) (name, version string) {
	if major == 0 {
		// Past the scope, a v5 key is "name/version": a '/' with no '@'
		// before it. A v6+ key reaches its '@' first ("name@version", and
		// "name@git+https://..." for a git dependency).
		first, _, slash := strings.Cut(pnpmScopeless(pnpmRelativePath(key)), "/")
		major = 6
		if slash && !strings.Contains(first, "@") {
			major = 5
		}
	}
	if major < 6 {
		return splitPnpmV5Key(key)
	}
	return splitPnpmV6Key(key)
}

// splitPnpmV5Key parses "/name/version[_peers]". The version is the last path
// segment: scoped names carry a '/', and a peer suffix never does, because v5
// writes a '/' inside one as '+' ("_@babel+core@7.16.0"). The suffix begins at
// the first '_' of that segment; package names may contain '_'
// (string_decoder), versions may not.
func splitPnpmV5Key(key string) (name, version string) {
	key = pnpmRelativePath(key)
	idx := strings.LastIndex(key, "/")
	if idx <= 0 {
		return "", ""
	}
	name, version = key[:idx], key[idx+1:]
	if cut := strings.IndexByte(version, '_'); cut >= 0 {
		version = version[:cut]
	}
	return name, version
}

// splitPnpmV6Key parses "/name@version(peers)" (6.0) and "name@version" (9.0).
// Everything from the first '(' is the peer or patch_hash suffix and may hold
// further '@'s, so it goes first; the separator is then the first '@' past the
// scope marker.
func splitPnpmV6Key(key string) (name, version string) {
	key = pnpmRelativePath(key)
	if cut := strings.IndexByte(key, '('); cut >= 0 {
		key = key[:cut]
	}
	start := 0
	if strings.HasPrefix(key, "@") {
		start = 1
	}
	idx := strings.IndexByte(key[start:], '@')
	if idx < 0 {
		return "", ""
	}
	return key[:start+idx], key[start+idx+1:]
}

// pnpmRelativePath strips the dependency path down to "name..." form. A
// registry package's path is relative ("/foo@1.0.0"); one from a registry other
// than the lockfile's default is absolute and prefixed with that registry's
// host ("registry.node-modules.io/foo@1.0.0", spec 5.2.md and 6.0.md).
// v9 keys are already bare.
func pnpmRelativePath(key string) string {
	if strings.HasPrefix(key, "/") {
		return key[1:]
	}
	if strings.HasPrefix(key, "@") {
		return key
	}
	host, rest, found := strings.Cut(key, "/")
	if found && strings.Contains(host, ".") && !strings.Contains(host, "@") {
		return rest
	}
	return key
}

// pnpmScopeless drops a leading "@scope/" so the '@' of a scope is not taken
// for a version separator.
func pnpmScopeless(key string) string {
	if strings.HasPrefix(key, "@") {
		if _, rest, found := strings.Cut(key, "/"); found {
			return rest
		}
	}
	return key
}

// pnpmLockfileMajor reads lockfileVersion, written as a number (5.4) before v6
// and as a string ('6.0', '9.0') since. Returns 0 when absent or unreadable.
func pnpmLockfileMajor(node *yaml.Node) int {
	if node == nil || node.Kind != yaml.ScalarNode {
		return 0
	}
	digits := node.Value
	if end := strings.IndexFunc(digits, func(r rune) bool { return r < '0' || r > '9' }); end >= 0 {
		digits = digits[:end]
	}
	major, err := strconv.Atoi(digits)
	if err != nil {
		return 0
	}
	return major
}

// yamlDocumentMapping returns the top-level mapping of a decoded document, or
// nil when the document is empty or not a mapping.
func yamlDocumentMapping(doc *yaml.Node) *yaml.Node {
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 {
		return nil
	}
	if root := doc.Content[0]; root.Kind == yaml.MappingNode {
		return root
	}
	return nil
}

// yamlMappingValue returns the value stored under key in a mapping node.
func yamlMappingValue(m *yaml.Node, key string) *yaml.Node {
	if m == nil || m.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(m.Content); i += 2 {
		if m.Content[i].Value == key {
			return m.Content[i+1]
		}
	}
	return nil
}
