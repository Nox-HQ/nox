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
	"openssl":           "pyopenssl",
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
	"dns":               "dnspython",
	"googleapiclient":   "google-api-python-client",
	"socks":             "pysocks",
	"pkg_resources":     "setuptools",
	"crypto":            "pycryptodome",
	"zmq":               "pyzmq",
	"mysqldb":           "mysqlclient",
	"git":               "gitpython",
	"ldap":              "python-ldap",
	"websocket":         "websocket-client",
	"wx":                "wxpython",
	"ruamel":            "ruamel.yaml",
	"_pytest":           "pytest",
	// pywin32 ships a family of extension modules under one distribution.
	"win32security":    "pywin32",
	"win32file":        "pywin32",
	"win32con":         "pywin32",
	"win32console":     "pywin32",
	"win32event":       "pywin32",
	"win32process":     "pywin32",
	"win32service":     "pywin32",
	"win32serviceutil": "pywin32",
	"win32gui":         "pywin32",
	"win32pipe":        "pywin32",
	"win32crypt":       "pywin32",
	"win32net":         "pywin32",
	"win32clipboard":   "pywin32",
	"win32profile":     "pywin32",
	"win32ts":          "pywin32",
	"pywintypes":       "pywin32",
	"pythoncom":        "pywin32",
	"ntsecuritycon":    "pywin32",
	"winerror":         "pywin32",
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
	// npmAliases are tsconfig/jsconfig `compilerOptions.paths` patterns, kept
	// verbatim (`@util/*`, `~/*`). A specifier one of these matches is resolved
	// by the bundler to a path inside the repository, so no registry serves it
	// and SLOP-001's proposition does not apply.
	npmAliases []string
}

func newDeclaredSet() *declaredSet {
	return &declaredSet{npm: map[string]struct{}{}, pypi: map[string]struct{}{}}
}

// addNPMAlias records one tsconfig `paths` pattern.
func (d *declaredSet) addNPMAlias(pattern string) {
	pattern = strings.TrimSpace(pattern)
	if pattern == "" {
		return
	}
	d.npmAliases = append(d.npmAliases, pattern)
}

// aliasFor reports the tsconfig `paths` pattern that resolves spec, if any.
//
// TypeScript allows at most one `*` per pattern and matches it greedily against
// the rest of the specifier; a pattern without `*` matches exactly. That is the
// whole of the matching rule, so this implements it rather than approximating
// it with a prefix test -- `@util/*` must not claim `@utilities/thing`.
//
// The aliases are collected across every tsconfig in the tree, which is wider
// than TypeScript's own scoping (a config applies to the files it includes).
// The direction of that imprecision is deliberate: SLOP-001 asserts a developer
// installed a package that does not exist, and a wrongly withheld finding costs
// less than that accusation made wrongly.
func (d *declaredSet) aliasFor(spec string) (string, bool) {
	for _, p := range d.npmAliases {
		star := strings.IndexByte(p, '*')
		if star < 0 {
			if spec == p {
				return p, true
			}
			continue
		}
		prefix, suffix := p[:star], p[star+1:]
		if len(spec) >= len(prefix)+len(suffix) &&
			strings.HasPrefix(spec, prefix) && strings.HasSuffix(spec, suffix) {
			return p, true
		}
	}
	return "", false
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
	raw := strings.TrimSpace(name)
	name = normalizePyPI(raw)
	if name == "" {
		return
	}
	d.pypi[name] = struct{}{}
	// A namespace-package distribution (zope.interface, backports.zoneinfo,
	// sphinxcontrib.spelling) is imported through its namespace root; the
	// dotted name is what identifies it as one.
	if i := strings.IndexByte(raw, '.'); i > 0 {
		d.pypi[normalizePyPI(raw[:i])] = struct{}{}
	}
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
	// The conventional ways a distribution decorates the module it ships:
	// python-digitalocean, python-augeas, python-dateutil; pyyaml, pyserial,
	// pyopenssl; kubernetes-python. The explicit table above covers the
	// names that follow no convention at all.
	for _, dist := range []string{"python-" + n, "py" + n, "py-" + n, n + "-python"} {
		if _, ok := d.pypi[dist]; ok {
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
		// Lockfiles carry the TRANSITIVE closure; a manifest carries only what
		// the project asked for directly. SLOP-001 reports an import that
		// resolves to nothing declared, so reading manifests alone makes every
		// transitive dependency a phantom import.
		//
		// Measured on the pinned corpus: `typing_extensions` was SLOP-001's
		// single largest name at 104 findings, `pydantic_core` 29, `botocore` 6
		// -- all real, all installed, all present in a lockfile nox was not
		// reading. `typing-extensions` appears 25 times in llama_index's
		// uv.lock alone. npm was already covered by package-lock.json; the
		// Python ecosystem had no lockfile reader at all, and pnpm and yarn
		// were missing on the npm side.
		case base == "poetry.lock" || base == "uv.lock" || base == "pdm.lock":
			parsePyLockTOML(content, d)
		case base == "pipfile.lock":
			parsePipfileLock(content, d)
		case base == "pnpm-lock.yaml" || base == "pnpm-lock.yml":
			parsePnpmLock(content, d)
		case base == "yarn.lock":
			parseYarnLock(content, d)
		// tsconfig `paths` is how a TypeScript project names its own source
		// without a relative path. `@util/chat-store` is a valid npm package
		// SHAPE, so unlike the empty-scope `@/components` case it cannot be
		// rejected on the name alone -- the config has to be read. 15 findings
		// in vercel/ai's examples/ai-e2e-next, whose tsconfig declares
		// "@util/*": ["./util/*"].
		case base == "tsconfig.json" || base == "jsconfig.json" ||
			strings.HasPrefix(base, "tsconfig.") && strings.HasSuffix(base, ".json"):
			parseTSConfigPaths(content, d)
		case base == "requirements.txt" || strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt"):
			parseRequirements(content, d)
		case base == "pyproject.toml":
			parsePyprojectDeps(content, d)
		case base == "pipfile":
			parsePipfile(content, d)
		case base == "setup.py":
			parseSetupPy(content, d)
		case base == "setup.cfg":
			parseSetupCfg(content, d)
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

// setupPyReqListRe finds the opening bracket of any requirement list in a
// setup.py: install_requires=[...], tests_require=[...], setup_requires=[...],
// the lists inside extras_require={...}, and the module-level variables those
// keyword arguments are commonly assigned from (`install_requires = [...]`).
var setupPyReqListRe = regexp.MustCompile(`(?i)(?:_requires?|extras_require)\s*=\s*[\[{(]`)

// parseSetupPy extracts requirement names from a setuptools setup.py without
// executing it. Nox never runs untrusted code, so this reads the literal lists
// only: from each requirement-list opener it walks to the matching closer and
// takes every string literal at any nesting depth, which covers extras_require
// dicts (whose keys are extra names, harmless as declarations) and lists built
// by concatenation. Requirements computed at runtime are invisible, and a
// setup.py that delegates everything to setup.cfg or pyproject.toml declares
// nothing here -- those files are parsed on their own.
func parseSetupPy(content []byte, d *declaredSet) {
	text := string(content)
	for _, loc := range setupPyReqListRe.FindAllStringIndex(text, -1) {
		for _, lit := range stringLiteralsInBrackets(text[loc[1]-1:]) {
			if n := pyReqNameRe.FindStringSubmatch(strings.TrimSpace(lit)); n != nil {
				d.addPyPI(n[1])
			}
		}
	}
}

// stringLiteralsInBrackets returns the quoted strings inside the bracketed
// expression that starts at s[0], stopping at the matching closer. Python
// string prefixes (f, r, u, b) are skipped so an f-string requirement such as
// f'acme>={version}' still yields its name.
func stringLiteralsInBrackets(s string) []string {
	var out []string
	depth := 0
	for i := 0; i < len(s); i++ {
		switch c := s[i]; c {
		case '[', '{', '(':
			depth++
		case ']', '}', ')':
			depth--
			if depth <= 0 {
				return out
			}
		case '#':
			for i < len(s) && s[i] != '\n' {
				i++
			}
		case '\'', '"':
			end := strings.IndexByte(s[i+1:], c)
			if end < 0 {
				return out
			}
			out = append(out, s[i+1:i+1+end])
			i += end + 1
		}
	}
	return out
}

// parseSetupCfg extracts requirement names from a setuptools setup.cfg: the
// install_requires / tests_require / setup_requires keys under [options] and
// every list under [options.extras_require]. Values are newline-separated,
// indented continuation lines; the single-line semicolon form is not
// supported by setuptools and not read here.
func parseSetupCfg(content []byte, d *declaredSet) {
	section := ""
	inList := false
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "[") {
			section = strings.ToLower(trimmed)
			inList = false
			continue
		}
		if trimmed == "" || strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
			continue
		}
		continuation := line != "" && (line[0] == ' ' || line[0] == '\t')
		if continuation {
			if inList {
				if n := pyReqNameRe.FindStringSubmatch(trimmed); n != nil {
					d.addPyPI(n[1])
				}
			}
			continue
		}
		inList = false
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		switch {
		case section == "[options]" && (key == "install_requires" || key == "tests_require" || key == "setup_requires"):
			inList = true
		case section == "[options.extras_require]":
			inList = true
		default:
			continue
		}
		// A value on the key line itself is the first requirement.
		if n := pyReqNameRe.FindStringSubmatch(strings.TrimSpace(value)); n != nil {
			d.addPyPI(n[1])
		}
	}
}

// pyLockPackageName matches the `name = "x"` line of a `[[package]]` table.
// poetry.lock, uv.lock and pdm.lock all use that shape.
var pyLockPackageName = regexp.MustCompile(`(?m)^\s*name\s*=\s*["']([A-Za-z0-9._-]+)["']`)

// parsePyLockTOML reads the package names out of a Python lockfile.
//
// It takes every `name = "..."` inside the file rather than tracking which
// table it is in. A lockfile's only named entities are its packages, and the
// alternative -- a TOML parser for three subtly different schemas -- buys
// precision this does not need: a name that is not a package still only ever
// makes a declared set LARGER, which suppresses a finding rather than inventing
// one. Erring that way is right here because the finding being suppressed is
// "this import resolves to nothing", and a wrong suppression is a missed
// phantom while a wrong report is an accusation of slopsquatting.
func parsePyLockTOML(content []byte, d *declaredSet) {
	for _, m := range pyLockPackageName.FindAllStringSubmatch(string(content), -1) {
		d.addPyPI(m[1])
	}
}

// parsePipfileLock reads Pipfile.lock, which is JSON with the package names as
// keys under "default" and "develop".
func parsePipfileLock(content []byte, d *declaredSet) {
	var lock map[string]map[string]json.RawMessage
	if err := json.Unmarshal(content, &lock); err != nil {
		return
	}
	for section, pkgs := range lock {
		if section == "_meta" {
			continue
		}
		for name := range pkgs {
			d.addPyPI(name)
		}
	}
}

// pnpmLockEntry matches a pnpm package key: two-space-indented
// `name@version:` or `'@scope/name@version':`, with or without pnpm v6's
// leading slash.
var pnpmLockEntry = regexp.MustCompile(`(?m)^ {2}'?/?((?:@[^/'@]+/)?[^'@\s/][^'@\s]*)@\d[^'\s]*'?:`)

// parsePnpmLock reads package names from a pnpm-lock.yaml.
func parsePnpmLock(content []byte, d *declaredSet) {
	for _, m := range pnpmLockEntry.FindAllStringSubmatch(string(content), -1) {
		d.addNPM(m[1])
	}
}

// yarnLockEntry matches the specifier heading of a yarn.lock stanza:
// `name@^1.0.0:` or `"@scope/name@^1.0.0":`, possibly several per line.
var yarnLockEntry = regexp.MustCompile(`(?m)^"?((?:@[^/"@]+/)?[^"@\s,]+)@[^"\s,]+`)

// parseYarnLock reads package names from a yarn.lock.
func parseYarnLock(content []byte, d *declaredSet) {
	for _, line := range strings.Split(string(content), "\n") {
		if line == "" || line[0] == ' ' || line[0] == '#' {
			continue // only a stanza heading starts at column 0
		}
		for _, part := range strings.Split(line, ", ") {
			if m := yarnLockEntry.FindStringSubmatch(strings.TrimSpace(part)); m != nil {
				d.addNPM(m[1])
			}
		}
	}
}

// tsconfig is JSONC — it permits comments and trailing commas, which
// encoding/json rejects — so the `paths` object is located textually and its
// keys read, rather than the file being unmarshalled. A tsconfig nox cannot
// parse must not become a tsconfig with no aliases: that silently restores the
// false positives the aliases exist to prevent.
var (
	tsPathsStartRe = regexp.MustCompile(`"paths"\s*:\s*\{`)
	tsPathsKeyRe   = regexp.MustCompile(`"([^"\n]+)"\s*:\s*\[`)
)

// parseTSConfigPaths records every `compilerOptions.paths` key as an alias.
//
// The object is delimited by brace matching, not by a regex for the closing
// brace. The first attempt used `(?s)"paths"\s*:\s*\{(.*?)\n\s*\}`, which
// needs the closing brace on its own line — true of every pretty-printed
// tsconfig and false of a minified one, so it read nothing from a single-line
// config and said nothing about it. Braces inside a string cannot be part of a
// path pattern, but they can appear in a comment, so string and comment state
// are both tracked.
func parseTSConfigPaths(content []byte, d *declaredSet) {
	loc := tsPathsStartRe.FindIndex(content)
	if loc == nil {
		return
	}
	depth, inStr, esc := 0, false, false
	end := -1
	for i := loc[1] - 1; i < len(content); i++ {
		c := content[i]
		switch {
		case esc:
			esc = false
		case inStr && c == '\\':
			esc = true
		case c == '"':
			inStr = !inStr
		case inStr:
		case c == '{':
			depth++
		case c == '}':
			depth--
			if depth == 0 {
				end = i
			}
		}
		if end >= 0 {
			break
		}
	}
	if end < 0 {
		return
	}
	for _, m := range tsPathsKeyRe.FindAllSubmatch(content[loc[1]:end], -1) {
		d.addNPMAlias(string(m[1]))
	}
}
