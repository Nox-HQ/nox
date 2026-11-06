package npmtree

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

// graph is one workspace's installed packages as its lockfile records them,
// whatever the package manager: each installed copy (node), what it asks for,
// and which copy a request resolves to. Reach and Below work on it, so npm,
// yarn and bun lockfiles answer the same questions the same way.
type graph struct {
	nodes map[string]node // by key: a lockfile path, an entry id
	// root is what the project itself declares, name -> range.
	root map[string]string
	// resolve is the key of the copy a request from the node at from ("" is
	// the project) for name at rng loads, or "".
	resolve func(from, name, rng string) string
}

type node struct {
	name, version string
	deps          map[string]string // name -> range, as the package declares it
}

func (g *graph) keys() []string {
	keys := make([]string, 0, len(g.nodes))
	for k := range g.nodes {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

// copies maps each copy of pkg to its version, by key.
func (g *graph) copies(pkg string) map[string]string {
	out := map[string]string{}
	for k, n := range g.nodes {
		if n.name == pkg {
			out[k] = n.version
		}
	}
	return out
}

// npmGraph is a package-lock.json: keys are node_modules paths, and a request
// loads the nearest copy on the way up from the requester.
func npmGraph(pkgs map[string]lockEntry) *graph {
	g := &graph{nodes: map[string]node{}, root: map[string]string{}}
	for path, e := range pkgs {
		deps := map[string]string{}
		for _, m := range []map[string]string{e.PeerDependencies, e.OptionalDependencies, e.Dependencies} {
			for n, r := range m {
				deps[n] = r
			}
		}
		if path == "" {
			for n, r := range e.DevDependencies {
				deps[n] = r
			}
			g.root = deps
			continue
		}
		g.nodes[path] = node{name: path[strings.LastIndex(path, "node_modules/")+len("node_modules/"):], version: e.Version, deps: deps}
	}
	g.resolve = func(from, name, _ string) string { return resolveCopy(pkgs, from, name) }
	return g
}

// yarnV1Graph is a yarn v1 lockfile: flat entries keyed by every "name@range"
// that resolved to them, each listing its own dependencies with ranges.
func yarnV1Graph(raw []byte, root map[string]string) *graph {
	g := &graph{nodes: map[string]node{}, root: root}
	bySpec := map[string]string{} // "name@range" -> key
	var cur *node
	var specs []string
	section := ""
	flush := func() {
		if cur == nil || cur.name == "" {
			return
		}
		key := cur.name + "@" + cur.version
		if existing, ok := g.nodes[key]; ok {
			for n, r := range cur.deps {
				existing.deps[n] = r
			}
		} else {
			g.nodes[key] = *cur
		}
		for _, s := range specs {
			bySpec[s] = key
		}
	}
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		trimmed := strings.TrimSpace(line)
		switch {
		case trimmed == "" || strings.HasPrefix(trimmed, "#"):
			continue
		case !strings.HasPrefix(line, " "):
			flush()
			cur, specs, section = &node{deps: map[string]string{}}, nil, ""
			for _, s := range strings.Split(strings.TrimSuffix(trimmed, ":"), ",") {
				s = strings.Trim(strings.TrimSpace(s), `"`)
				specs = append(specs, s)
				if name, _, ok := splitSpec(s); ok {
					cur.name = name
				}
			}
		case strings.HasPrefix(line, "    "):
			if section == "dependencies" || section == "optionalDependencies" {
				name, rng, ok := strings.Cut(trimmed, " ")
				if ok {
					cur.deps[strings.Trim(name, `"`)] = strings.Trim(strings.TrimSpace(rng), `"`)
				}
			}
		default: // two-space field of the current entry
			field, value, _ := strings.Cut(trimmed, " ")
			section = strings.TrimSuffix(field, ":")
			if field == "version" {
				cur.version = strings.Trim(value, `"`)
			}
		}
	}
	flush()
	g.resolve = func(_, name, rng string) string { return bySpec[name+"@"+rng] }
	return g
}

// splitSpec splits "name@range" at the "@" after a scope.
func splitSpec(s string) (name, rng string, ok bool) {
	at := strings.LastIndex(s, "@")
	if at <= 0 {
		return "", "", false
	}
	return s[:at], s[at+1:], true
}

// trailingComma drops the trailing commas JSONC allows and JSON does not.
var trailingComma = regexp.MustCompile(`,(\s*[}\]])`)

// bunGraph is a text bun.lock: entries are [ident, registry, metadata,
// integrity] under keys that nest like npm's paths ("parent/child" is the
// parent's own copy), and the project's ranges are workspaces[""].
func bunGraph(raw []byte) (*graph, bool) {
	var lock struct {
		Workspaces map[string]map[string]json.RawMessage `json:"workspaces"`
		Packages   map[string][]json.RawMessage          `json:"packages"`
	}
	if json.Unmarshal(trailingComma.ReplaceAll(raw, []byte("$1")), &lock) != nil || len(lock.Packages) == 0 {
		return nil, false
	}
	g := &graph{nodes: map[string]node{}, root: map[string]string{}}
	for _, section := range []string{"dependencies", "devDependencies", "optionalDependencies"} {
		var m map[string]string
		if json.Unmarshal(lock.Workspaces[""][section], &m) == nil {
			for n, r := range m {
				g.root[n] = r
			}
		}
	}
	for key, entry := range lock.Packages {
		if len(entry) == 0 {
			continue
		}
		var ident string
		if json.Unmarshal(entry[0], &ident) != nil {
			continue
		}
		name, version, ok := splitSpec(ident)
		if !ok {
			continue
		}
		n := node{name: name, version: version, deps: map[string]string{}}
		if len(entry) > 2 {
			var meta map[string]map[string]string
			_ = json.Unmarshal(entry[2], &meta)
			for _, section := range []string{"peerDependencies", "optionalDependencies", "dependencies"} {
				for d, r := range meta[section] {
					n.deps[d] = r
				}
			}
		}
		g.nodes[key] = n
	}
	g.resolve = func(from, name, _ string) string {
		for cur := from; ; {
			cand := name
			if cur != "" {
				cand = cur + "/" + name
			}
			if _, ok := g.nodes[cand]; ok {
				return cand
			}
			if cur == "" {
				return ""
			}
			cur = bunParent(cur)
		}
	}
	return g, true
}

// bunParent drops the last package name from a bun.lock key, minding scopes:
// "a/@s/b" -> "a", "@s/a/b" -> "@s/a", "a" -> "".
func bunParent(key string) string {
	segs := strings.Split(key, "/")
	var names []string
	for i := 0; i < len(segs); i++ {
		if strings.HasPrefix(segs[i], "@") && i+1 < len(segs) {
			names = append(names, segs[i]+"/"+segs[i+1])
			i++
			continue
		}
		names = append(names, segs[i])
	}
	if len(names) <= 1 {
		return ""
	}
	return strings.Join(names[:len(names)-1], "/")
}

// pnpmKey is a package key in pnpm-lock.yaml's packages section: v9
// "name@version", v6 "/name@version", v5 "/name/version", each with an
// optional peer suffix "(…)" or "_…".
var pnpmKey = regexp.MustCompile(`^ {2}'?/?((?:@[^/@']+/)?[^/@'(]+)[@/](\d[^'(_:]*)`)

// pnpmCopies reads the resolved versions in pnpm-lock.yaml's packages
// section. pnpm records what each dependent resolved, not the range it
// allows, so this answers Below, never Reach.
func pnpmCopies(raw []byte) map[string]node {
	nodes := map[string]node{}
	inPackages := false
	sc := bufio.NewScanner(strings.NewReader(string(raw)))
	sc.Buffer(make([]byte, 0, 64*1024), 16<<20)
	for sc.Scan() {
		line := sc.Text()
		if !strings.HasPrefix(line, " ") && strings.TrimSpace(line) != "" {
			inPackages = strings.HasPrefix(line, "packages:")
			continue
		}
		if !inPackages {
			continue
		}
		if m := pnpmKey.FindStringSubmatch(line); m != nil {
			key := m[1] + "@" + m[2]
			nodes[key] = node{name: m[1], version: m[2]}
		}
	}
	return nodes
}

// readManifestDeps is what the project's package.json declares, name ->
// range, for lockfiles that do not record it (yarn v1).
func readManifestDeps(dir string) map[string]string {
	raw, err := os.ReadFile(filepath.Join(dir, "package.json")) //nolint:gosec // dir is the project under scan or fix
	if err != nil {
		return map[string]string{}
	}
	var manifest map[string]json.RawMessage
	if json.Unmarshal(raw, &manifest) != nil {
		return map[string]string{}
	}
	out := map[string]string{}
	for _, section := range []string{"devDependencies", "optionalDependencies", "dependencies"} {
		var deps map[string]string
		if json.Unmarshal(manifest[section], &deps) == nil {
			for n, r := range deps {
				out[n] = r
			}
		}
	}
	return out
}
