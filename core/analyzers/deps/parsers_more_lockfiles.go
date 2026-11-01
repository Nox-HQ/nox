package deps

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// Lockfile parsers for SwiftPM, Mix, Gradle dependency locking, CocoaPods and
// Conan. Unlike the older tolerant parsers, these return an error for content
// they cannot read: the caller turns an error into a degradation, and a
// lockfile that parsed to nothing without complaint is how an ecosystem scans
// clean while unread. Empty input is "no packages", not an error.
//
// Ecosystem names are the manifest table's. Only "hex" and "gradle" (OSV's
// Maven) are queryable through the advisory pipeline; "swift", "cocoapods" and
// "conan" are inventoried and reported as unchecked, see
// reportUnqueryableEcosystems.

func isBlank(content []byte) bool { return len(bytes.TrimSpace(content)) == 0 }

// packageResolved is both layouts of SwiftPM's Package.resolved: v1 nests the
// pins under "object" and names them by "repositoryURL"; v2 and v3 are flat and
// use "location".
type packageResolved struct {
	Object struct {
		Pins []resolvedPin `json:"pins"`
	} `json:"object"`
	Pins []resolvedPin `json:"pins"`
}

type resolvedPin struct {
	RepositoryURL string `json:"repositoryURL"`
	Location      string `json:"location"`
	State         struct {
		Version *string `json:"version"`
	} `json:"state"`
}

// parsePackageResolved reads Package.resolved. The package name is the
// repository URL, which is how OSV's SwiftURL ecosystem names a package. A pin
// at a branch or revision has no version and is skipped: there is nothing to
// match an advisory's range against.
func parsePackageResolved(content []byte) ([]Package, error) {
	if isBlank(content) {
		return nil, nil
	}
	var doc packageResolved
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parsing Package.resolved: %w", err)
	}
	var pkgs []Package
	seen := map[string]struct{}{}
	for _, pin := range append(doc.Object.Pins, doc.Pins...) {
		url := pin.Location
		if url == "" {
			url = pin.RepositoryURL
		}
		if url == "" || pin.State.Version == nil || *pin.State.Version == "" {
			continue
		}
		url = swiftPackageName(url)
		key := url + "@" + *pin.State.Version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, Package{Name: url, Version: *pin.State.Version, Ecosystem: "swift"})
	}
	return pkgs, nil
}

// reMixHex matches a Hex entry of mix.lock. The second atom is the package's
// name on Hex, which differs from the map key when a dependency is renamed.
var reMixHex = regexp.MustCompile(`^\s*"[^"]+":\s*\{:hex,\s*:([A-Za-z0-9_]+),\s*"([^"]+)"`)

// reMixEntry matches any entry, so a Hex entry reMixHex cannot read is an error
// while git and path entries are skipped.
var reMixEntry = regexp.MustCompile(`^\s*"[^"]+":\s*\{:([a-z]+)\b`)

// parseMixLock reads Elixir's mix.lock, a map literal with one dependency per
// line. Git dependencies carry no registry version and are skipped.
func parseMixLock(content []byte) ([]Package, error) {
	if isBlank(content) {
		return nil, nil
	}
	trimmed := bytes.TrimSpace(content)
	if !bytes.HasPrefix(trimmed, []byte("%{")) || !bytes.HasSuffix(trimmed, []byte("}")) {
		return nil, errors.New("mix.lock is not an Elixir map literal (%{ ... })")
	}
	var pkgs []Package
	seen := map[string]struct{}{}
	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		entry := reMixEntry.FindStringSubmatch(line)
		if len(entry) < 2 || entry[1] != "hex" {
			continue
		}
		m := reMixHex.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("mix.lock entry has no version: %s", strings.TrimSpace(line))
		}
		key := m[1] + "@" + m[2]
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, Package{Name: m[1], Version: m[2], Ecosystem: "hex"})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning mix.lock: %w", err)
	}
	return pkgs, nil
}

var reGradleLock = regexp.MustCompile(`^([^:\s=]+):([^:\s=]+):([^=\s]+)=\S*$`)

// parseGradleLockfile reads gradle.lockfile, one `group:artifact:version=configs`
// line per resolved module. The ecosystem is "gradle", which OSV queries as
// Maven. A module locked in several configurations is one package.
func parseGradleLockfile(content []byte) ([]Package, error) {
	var pkgs []Package
	seen := map[string]struct{}{}
	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "empty=") {
			continue
		}
		m := reGradleLock.FindStringSubmatch(line)
		if m == nil {
			return nil, fmt.Errorf("gradle.lockfile line is not group:artifact:version=configurations: %q", line)
		}
		name := m[1] + ":" + m[2]
		key := name + "@" + m[3]
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, Package{Name: name, Version: m[3], Ecosystem: "gradle"})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning gradle.lockfile: %w", err)
	}
	return pkgs, nil
}

var rePodEntry = regexp.MustCompile(`^"?([^\s"(]+)\s+\(([^)]+)\)"?:?$`)

// parsePodfileLock reads the PODS section of Podfile.lock. Subspecs
// (`Firebase/Core`) are parts of their root pod, which is the unit CocoaPods
// advisories name, so they collapse into it. A pod sourced from a path or
// repository (`Local (from ...)`) has no registry version and is skipped.
func parsePodfileLock(content []byte) ([]Package, error) {
	if isBlank(content) {
		return nil, nil
	}
	var pkgs []Package
	seen := map[string]struct{}{}
	inPods, sawPods := false, false
	scanner := newLineScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := scanner.Text()
		if strings.TrimSpace(line) == "" {
			continue
		}
		if !strings.HasPrefix(line, " ") {
			inPods = strings.HasPrefix(line, "PODS:")
			sawPods = sawPods || inPods
			continue
		}
		// Top-level pods sit at two spaces; their dependencies at four.
		if !inPods || !strings.HasPrefix(line, "  - ") {
			continue
		}
		m := rePodEntry.FindStringSubmatch(strings.TrimSpace(strings.TrimPrefix(line, "  - ")))
		if m == nil {
			return nil, fmt.Errorf("in Podfile.lock, pod is not `Name (version)`: %q", strings.TrimSpace(line))
		}
		if strings.HasPrefix(m[2], "from ") {
			continue
		}
		name, _, _ := strings.Cut(m[1], "/")
		key := name + "@" + m[2]
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, Package{Name: name, Version: m[2], Ecosystem: "cocoapods"})
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scanning Podfile.lock: %w", err)
	}
	if !sawPods {
		return nil, errors.New("no PODS section in Podfile.lock")
	}
	return pkgs, nil
}

// conanLock covers the 2.x format ("requires" lists) and the 1.x graph_lock.
type conanLock struct {
	Requires      []string `json:"requires"`
	BuildRequires []string `json:"build_requires"`
	GraphLock     *struct {
		Nodes map[string]struct {
			Ref  string `json:"ref"`
			Pref string `json:"pref"`
		} `json:"nodes"`
	} `json:"graph_lock"`
}

// parseConanRef reduces `name/1.2.3@user/channel#rev:id#prev` to name and version.
func parseConanRef(ref string) (name, version string, err error) {
	base := ref
	for _, sep := range []string{"#", "@", ":"} {
		base, _, _ = strings.Cut(base, sep)
	}
	name, version, ok := strings.Cut(base, "/")
	if !ok || name == "" || version == "" {
		return "", "", fmt.Errorf("conan reference %q is not name/version", ref)
	}
	return name, version, nil
}

// parseConanLock reads conan.lock. Build requirements are dependencies of the
// build and are included; python_requires are recipes, not packages, and are
// not. The graph_lock root node (0) is the consumer itself.
func parseConanLock(content []byte) ([]Package, error) {
	if isBlank(content) {
		return nil, nil
	}
	var doc conanLock
	if err := json.Unmarshal(content, &doc); err != nil {
		return nil, fmt.Errorf("parsing conan.lock: %w", err)
	}
	if doc.GraphLock == nil && doc.Requires == nil && doc.BuildRequires == nil {
		return nil, errors.New("conan.lock has neither requires nor graph_lock")
	}
	refs := append(append([]string{}, doc.Requires...), doc.BuildRequires...)
	if doc.GraphLock != nil {
		for id, n := range doc.GraphLock.Nodes {
			switch {
			case id == "0":
			case n.Ref != "":
				refs = append(refs, n.Ref)
			case n.Pref != "":
				refs = append(refs, n.Pref)
			}
		}
	}
	var pkgs []Package
	seen := map[string]struct{}{}
	for _, ref := range refs {
		name, version, err := parseConanRef(ref)
		if err != nil {
			return nil, err
		}
		key := name + "@" + version
		if _, dup := seen[key]; dup {
			continue
		}
		seen[key] = struct{}{}
		pkgs = append(pkgs, Package{Name: name, Version: version, Ecosystem: "conan"})
	}
	sort.SliceStable(pkgs, func(i, j int) bool {
		if pkgs[i].Name != pkgs[j].Name {
			return pkgs[i].Name < pkgs[j].Name
		}
		return pkgs[i].Version < pkgs[j].Version
	})
	return pkgs, nil
}

// swiftPackageName is a SwiftPM location in the form OSV's SwiftURL ecosystem
// names packages: host and path, no scheme, user, ".git" or trailing slash
// ("https://github.com/vapor/vapor.git" -> "github.com/vapor/vapor"). Case is
// kept, since OSV matches names exactly.
func swiftPackageName(location string) string {
	s := strings.TrimSpace(location)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	} else if at := strings.Index(s, "@"); at >= 0 {
		// scp-like: git@github.com:owner/repo
		s = strings.Replace(s[at+1:], ":", "/", 1)
	}
	if at := strings.Index(s, "@"); at >= 0 && at < strings.Index(s+"/", "/") {
		s = s[at+1:] // user in a URL: ssh://git@host/...
	}
	s = strings.TrimSuffix(strings.TrimSuffix(s, "/"), ".git")
	return s
}
