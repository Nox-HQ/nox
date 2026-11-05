package deps

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
)

// npmManifests answers whether a project lists an npm package itself, from the
// package.json beside the lockfile the package came from. Read once per
// directory.
type npmManifests struct {
	mu    sync.Mutex
	byDir map[string]map[string]bool // nil entry: no readable package.json
}

// declares reports whether the package.json in dir lists pkg, and whether that
// could be established at all. A manifest nox did not read establishes nothing.
func (m *npmManifests) declares(dir, pkg string) (listed, known bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.byDir == nil {
		m.byDir = map[string]map[string]bool{}
	}
	deps, seen := m.byDir[dir]
	if !seen {
		deps = readNPMDeclared(dir)
		m.byDir[dir] = deps
	}
	if deps == nil {
		return false, false
	}
	return deps[pkg], true
}

func readNPMDeclared(dir string) map[string]bool {
	data, err := os.ReadFile(filepath.Join(dir, "package.json")) //nolint:gosec // dir holds a scanned lockfile
	if err != nil {
		return nil
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(data, &manifest) != nil {
		return nil
	}
	declared := map[string]bool{}
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies", "peerDependencies"} {
		var deps map[string]string
		if json.Unmarshal(manifest[section], &deps) != nil {
			continue
		}
		for name := range deps {
			declared[name] = true
		}
	}
	return declared
}

// transitiveRemediationNote is what a transitive npm finding says instead of an
// install command: installing the fixed version would add a second, direct copy
// and leave the one the parent resolves vulnerable.
const transitiveRemediationNote = "not listed in package.json: the packages that depend on it decide whether it can move. " +
	"`npm install` would add a separate direct copy and leave theirs unfixed; nox fix plan names what holds it and the overrides entry that forces it"
