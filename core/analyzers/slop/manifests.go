package slop

import (
	"embed"
	"encoding/json"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

//go:embed data/python_stdlib.txt data/node_builtins.txt
var dataFS embed.FS

var (
	stdlibOnce sync.Once
	pyStdlib   map[string]struct{}
	nodeStdlib map[string]struct{}
)

func loadStdlib() {
	pyStdlib = readSet("data/python_stdlib.txt")
	nodeStdlib = readSet("data/node_builtins.txt")
}

func readSet(path string) map[string]struct{} {
	set := make(map[string]struct{})
	data, err := dataFS.ReadFile(path)
	if err != nil {
		return set
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		set[line] = struct{}{}
	}
	return set
}

// isStdlib reports whether name is a standard-library / builtin module for eco.
func isStdlib(eco ecosystem, name string) bool {
	stdlibOnce.Do(loadStdlib)
	switch eco {
	case ecoPyPI:
		_, ok := pyStdlib[name]
		return ok
	case ecoNPM:
		_, ok := nodeStdlib[name]
		return ok
	}
	return false
}

// importToDist maps well-known Python import names to their PyPI distribution
// name, covering the common cases where the two differ. Without this, a scanned
// `import yaml` backed by a declared `pyyaml` dependency would be a false
// positive. Keys and values are normalized (lowercase, hyphens).
var importToDist = map[string]string{
	"yaml":              "pyyaml",
	"cv2":               "opencv-python",
	"pil":               "pillow",
	"sklearn":           "scikit-learn",
	"bs4":               "beautifulsoup4",
	"dotenv":            "python-dotenv",
	"jwt":               "pyjwt",
	"dateutil":          "python-dateutil",
	"google":            "google-api-python-client",
	"serial":            "pyserial",
	"usb":               "pyusb",
	"win32api":          "pywin32",
	"win32com":          "pywin32",
	"attr":              "attrs",
	"markdown":          "markdown",
	"docx":              "python-docx",
	"pptx":              "python-pptx",
	"cairo":             "pycairo",
	"gi":                "pygobject",
	"OpenSSL":           "pyopenssl",
	"cryptography":      "cryptography",
	"magic":             "python-magic",
	"redis":             "redis",
	"psycopg2":          "psycopg2-binary",
	"grpc":              "grpcio",
	"jose":              "python-jose",
	"slugify":           "python-slugify",
	"multipart":         "python-multipart",
	"nacl":              "pynacl",
	"zoneinfo_backport": "backports.zoneinfo",
}

// normalizePyPI lowercases and unifies separators per PEP 503 so that
// "Flask_Login", "flask-login" and "flask.login" compare equal.
func normalizePyPI(name string) string {
	name = strings.ToLower(strings.TrimSpace(name))
	name = strings.NewReplacer("_", "-", ".", "-").Replace(name)
	// Collapse runs of hyphens (PEP 503 canonical form).
	for strings.Contains(name, "--") {
		name = strings.ReplaceAll(name, "--", "-")
	}
	return name
}

// declaredSet holds the set of package names a project declares, per ecosystem.
type declaredSet struct {
	npm  map[string]struct{} // exact names (scoped kept as @scope/name)
	pypi map[string]struct{} // normalized (normalizePyPI) names
}

func newDeclaredSet() *declaredSet {
	return &declaredSet{npm: map[string]struct{}{}, pypi: map[string]struct{}{}}
}

func (d *declaredSet) addNPM(name string) {
	name = strings.TrimSpace(name)
	if name == "" {
		return
	}
	d.npm[name] = struct{}{}
	// A declared @types/foo type stub vouches for the runtime package foo.
	if strings.HasPrefix(name, "@types/") {
		d.npm[strings.TrimPrefix(name, "@types/")] = struct{}{}
	}
}

func (d *declaredSet) addPyPI(name string) {
	name = normalizePyPI(name)
	if name == "" {
		return
	}
	d.pypi[name] = struct{}{}
}

// hasNPM reports whether an npm package (top-level name) is declared.
func (d *declaredSet) hasNPM(name string) bool {
	_, ok := d.npm[name]
	return ok
}

// hasPyPI reports whether a Python import root maps to a declared distribution.
func (d *declaredSet) hasPyPI(importRoot string) bool {
	n := normalizePyPI(importRoot)
	if _, ok := d.pypi[n]; ok {
		return true
	}
	if dist, ok := importToDist[strings.ToLower(importRoot)]; ok {
		if _, ok := d.pypi[normalizePyPI(dist)]; ok {
			return true
		}
	}
	return false
}

var pyReqNameRe = regexp.MustCompile(`^([A-Za-z0-9][A-Za-z0-9._-]*)`)

// collectDeclared parses the common dependency manifests among artifacts and
// returns the union of declared package names per ecosystem. It reads bytes via
// readFile (injectable for tests).
func collectDeclared(files map[string][]byte) *declaredSet {
	d := newDeclaredSet()
	for path, content := range files {
		base := strings.ToLower(filepath.Base(path))
		switch {
		case base == "package.json":
			parsePackageJSON(content, d)
		case base == "package-lock.json":
			parsePackageLock(content, d)
		case base == "requirements.txt" || strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			parseRequirements(content, d)
		case base == "pyproject.toml":
			parsePyprojectDeps(content, d)
		case base == "pipfile":
			parsePipfile(content, d)
		}
	}
	return d
}

func parsePackageJSON(content []byte, d *declaredSet) {
	var pkg struct {
		Dependencies         map[string]string `json:"dependencies"`
		DevDependencies      map[string]string `json:"devDependencies"`
		PeerDependencies     map[string]string `json:"peerDependencies"`
		OptionalDependencies map[string]string `json:"optionalDependencies"`
		Workspaces           json.RawMessage   `json:"workspaces"`
		Name                 string            `json:"name"`
	}
	if err := json.Unmarshal(content, &pkg); err != nil {
		return
	}
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDependencies, pkg.OptionalDependencies} {
		for name := range m {
			d.addNPM(name)
		}
	}
	// The workspace root's own name is a valid local specifier.
	if pkg.Name != "" {
		d.addNPM(pkg.Name)
	}
}

func parsePackageLock(content []byte, d *declaredSet) {
	var lock struct {
		Packages     map[string]json.RawMessage `json:"packages"`
		Dependencies map[string]json.RawMessage `json:"dependencies"`
	}
	if err := json.Unmarshal(content, &lock); err != nil {
		return
	}
	for path := range lock.Packages {
		if path == "" {
			continue
		}
		// Keys look like "node_modules/@scope/name" or "node_modules/name".
		i := strings.LastIndex(path, "node_modules/")
		if i < 0 {
			continue
		}
		d.addNPM(path[i+len("node_modules/"):])
	}
	for name := range lock.Dependencies { // legacy lockfile v1 shape
		d.addNPM(name)
	}
}

func parseRequirements(content []byte, d *declaredSet) {
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "-") {
			continue // skip options like -r, -e, --hash
		}
		if m := pyReqNameRe.FindStringSubmatch(line); m != nil {
			d.addPyPI(m[1])
		}
	}
}

// parsePyprojectDeps extracts dependency names from a pyproject.toml without a
// full TOML parser: it scans PEP 621 [project] dependencies and Poetry
// [tool.poetry.dependencies] entries, which is sufficient to vouch for imports.
func parsePyprojectDeps(content []byte, d *declaredSet) {
	text := string(content)
	// PEP 621: dependencies = ["flask>=2", "requests"]
	for _, m := range tomlArrayReqRe.FindAllStringSubmatch(text, -1) {
		if n := pyReqNameRe.FindStringSubmatch(strings.TrimSpace(m[1])); n != nil {
			d.addPyPI(n[1])
		}
	}
	// Poetry: under [tool.poetry.dependencies], lines like `flask = "^2.0"`.
	inPoetry := false
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inPoetry = strings.Contains(trimmed, "poetry") && strings.Contains(trimmed, "dependencies")
			continue
		}
		if !inPoetry || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if i := strings.IndexByte(trimmed, '='); i > 0 {
			name := strings.TrimSpace(trimmed[:i])
			if strings.EqualFold(name, "python") {
				continue
			}
			if n := pyReqNameRe.FindStringSubmatch(name); n != nil {
				d.addPyPI(n[1])
			}
		}
	}
}

var tomlArrayReqRe = regexp.MustCompile(`["']([A-Za-z0-9][A-Za-z0-9._-]*(?:\s*[<>=!~][^"']*)?)["']`)

func parsePipfile(content []byte, d *declaredSet) {
	inDeps := false
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			inDeps = strings.Contains(trimmed, "packages")
			continue
		}
		if !inDeps || trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if i := strings.IndexByte(trimmed, '='); i > 0 {
			if n := pyReqNameRe.FindStringSubmatch(strings.TrimSpace(trimmed[:i])); n != nil {
				d.addPyPI(n[1])
			}
		}
	}
}
