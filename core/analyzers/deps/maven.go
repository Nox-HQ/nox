package deps

import (
	"encoding/xml"
	"fmt"
	"path"
	"sort"
	"strings"
)

// A Maven dependency usually carries no literal version. Spring Boot, Quarkus
// and nearly every multi-module build take it from a parent POM's
// dependencyManagement, from an imported BOM, or from ${some.version}; on the
// repositories measured, 96–99% of declared dependencies had no literal
// version, and reading only literals checked almost nothing while reporting
// nothing about the rest.
//
// mavenIndex resolves what the repository itself can answer, offline: the
// pom's own properties, the properties and dependencyManagement of a parent
// that is in the repository, and BOMs imported from the repository. A version
// that comes from a parent or BOM published elsewhere (spring-boot-starter-parent,
// quarkus-bom) is not guessed: the dependency is reported as unresolved, naming
// where its version lives, and the scan records that it was NOT checked.

// maxPomDepth bounds parent chains and BOM imports. Real chains are a handful
// deep; the bound only stops a malformed or hostile cycle.
const maxPomDepth = 16

// maxInterpolation bounds ${...} substitution rounds for the same reason.
const maxInterpolation = 10

type pomCoords struct{ group, artifact, version string }

func (c pomCoords) String() string { return c.group + ":" + c.artifact + ":" + c.version }

type pomDep struct {
	group, artifact, version, scope, typ string
}

type pomFile struct {
	path      string // slash-separated, relative to the scan root
	coords    pomCoords
	parent    *pomCoords
	relPath   string // parent relativePath; "" when the element is empty
	relSet    bool   // the relativePath element is present
	props     map[string]string
	managed   []pomDep
	deps      []pomDep
	parseFail error
}

type pomEntry struct {
	XMLName xml.Name
	Value   string `xml:",chardata"`
}

type pomDepXML struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
}

type pomDocXML struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Parent     *struct {
		GroupID      string  `xml:"groupId"`
		ArtifactID   string  `xml:"artifactId"`
		Version      string  `xml:"version"`
		RelativePath *string `xml:"relativePath"`
	} `xml:"parent"`
	Properties struct {
		Entries []pomEntry `xml:",any"`
	} `xml:"properties"`
	Dependencies struct {
		Dependency []pomDepXML `xml:"dependency"`
	} `xml:"dependencies"`
	DependencyManagement struct {
		Dependencies struct {
			Dependency []pomDepXML `xml:"dependency"`
		} `xml:"dependencies"`
	} `xml:"dependencyManagement"`
}

func parsePomFile(p string, content []byte) *pomFile {
	var doc pomDocXML
	f := &pomFile{path: p, props: map[string]string{}}
	if err := xml.Unmarshal(content, &doc); err != nil {
		f.parseFail = fmt.Errorf("parsing pom.xml: %w", err)
		return f
	}
	f.coords = pomCoords{strings.TrimSpace(doc.GroupID), strings.TrimSpace(doc.ArtifactID), strings.TrimSpace(doc.Version)}
	if doc.Parent != nil {
		pc := pomCoords{strings.TrimSpace(doc.Parent.GroupID), strings.TrimSpace(doc.Parent.ArtifactID), strings.TrimSpace(doc.Parent.Version)}
		f.parent = &pc
		if doc.Parent.RelativePath != nil {
			f.relSet = true
			f.relPath = strings.TrimSpace(*doc.Parent.RelativePath)
		}
		// groupId and version are inherited from the parent when absent.
		if f.coords.group == "" {
			f.coords.group = pc.group
		}
		if f.coords.version == "" {
			f.coords.version = pc.version
		}
	}
	for _, e := range doc.Properties.Entries {
		f.props[e.XMLName.Local] = strings.TrimSpace(e.Value)
	}
	conv := func(in []pomDepXML) []pomDep {
		out := make([]pomDep, 0, len(in))
		for _, d := range in {
			out = append(out, pomDep{
				group: strings.TrimSpace(d.GroupID), artifact: strings.TrimSpace(d.ArtifactID),
				version: strings.TrimSpace(d.Version), scope: strings.TrimSpace(d.Scope), typ: strings.TrimSpace(d.Type),
			})
		}
		return out
	}
	f.deps = conv(doc.Dependencies.Dependency)
	f.managed = conv(doc.DependencyManagement.Dependencies.Dependency)
	return f
}

// mavenIndex holds every pom.xml of one scan.
type mavenIndex struct {
	byPath map[string]*pomFile
	byGA   map[string]*pomFile // groupId:artifactId of each in-repo module
}

func newMavenIndex() *mavenIndex {
	return &mavenIndex{byPath: map[string]*pomFile{}, byGA: map[string]*pomFile{}}
}

func (x *mavenIndex) add(p string, content []byte) {
	f := parsePomFile(p, content)
	x.byPath[p] = f
	if f.parseFail == nil && f.coords.group != "" && f.coords.artifact != "" {
		ga := f.coords.group + ":" + f.coords.artifact
		// The first by path wins, so the result never depends on map order.
		if old, ok := x.byGA[ga]; !ok || p < old.path {
			x.byGA[ga] = f
		}
	}
}

// parentOf returns the in-repo parent of f, or nil when the parent is
// published elsewhere (or absent). The relativePath (default ../pom.xml) is
// tried first, as Maven does, and accepted only when its coordinates match;
// otherwise the parent is found by coordinates among the repository's modules.
func (x *mavenIndex) parentOf(f *pomFile) *pomFile {
	if f.parent == nil {
		return nil
	}
	rel := "../pom.xml"
	if f.relSet {
		rel = f.relPath
	}
	if rel != "" {
		cand := path.Clean(path.Join(path.Dir(f.path), rel))
		if !strings.HasSuffix(cand, "pom.xml") {
			cand = path.Join(cand, "pom.xml")
		}
		if p, ok := x.byPath[cand]; ok && p.parseFail == nil &&
			p.coords.group == f.parent.group && p.coords.artifact == f.parent.artifact {
			return p
		}
	}
	if p, ok := x.byGA[f.parent.group+":"+f.parent.artifact]; ok && p != f {
		return p
	}
	return nil
}

// chain is f followed by its in-repo ancestors, and the first ancestor that is
// NOT in the repository (nil when the chain ends locally).
func (x *mavenIndex) chain(f *pomFile) ([]*pomFile, *pomCoords) {
	out := []*pomFile{f}
	seen := map[*pomFile]bool{f: true}
	cur := f
	for range maxPomDepth {
		if cur.parent == nil {
			return out, nil
		}
		p := x.parentOf(cur)
		if p == nil {
			return out, cur.parent
		}
		if seen[p] {
			return out, nil
		}
		seen[p] = true
		out = append(out, p)
		cur = p
	}
	return out, nil
}

// properties is f's effective property set: its own over its ancestors', with
// the project.* built-ins.
func (x *mavenIndex) properties(f *pomFile) map[string]string {
	ch, _ := x.chain(f)
	props := map[string]string{}
	for i := len(ch) - 1; i >= 0; i-- {
		for k, v := range ch[i].props {
			props[k] = v
		}
	}
	props["project.groupId"] = f.coords.group
	props["project.artifactId"] = f.coords.artifact
	props["project.version"] = f.coords.version
	props["pom.version"] = f.coords.version
	props["version"] = f.coords.version
	if f.parent != nil {
		props["project.parent.version"] = f.parent.version
		props["parent.version"] = f.parent.version
		props["project.parent.groupId"] = f.parent.group
	}
	return props
}

// interpolate substitutes ${...} references. ok is false when one remains.
func interpolate(s string, props map[string]string) (string, bool) {
	for range maxInterpolation {
		i := strings.Index(s, "${")
		if i < 0 {
			return s, true
		}
		j := strings.IndexByte(s[i:], '}')
		if j < 0 {
			return s, false
		}
		v, ok := props[s[i+2:i+j]]
		if !ok {
			return s, false
		}
		s = s[:i] + v + s[i+j+1:]
	}
	return s, !strings.Contains(s, "${")
}

// managedVersions is the groupId:artifactId → version table f's dependencies
// draw on, from f and its in-repo ancestors (nearest wins) and the BOMs they
// import from the repository. external names imported BOMs that are not.
func (x *mavenIndex) managedVersions(f *pomFile, depth int, visiting map[*pomFile]bool) (map[string]string, []pomCoords) {
	table := map[string]string{}
	var external []pomCoords
	if depth > maxPomDepth || visiting[f] {
		return table, nil
	}
	visiting[f] = true
	defer delete(visiting, f)
	props := x.properties(f)
	ch, _ := x.chain(f)
	for _, p := range ch {
		for _, m := range p.managed {
			g, okG := interpolate(m.group, props)
			a, okA := interpolate(m.artifact, props)
			if !okG || !okA {
				continue
			}
			if m.scope == "import" {
				v, _ := interpolate(m.version, props)
				bom, ok := x.byGA[g+":"+a]
				if !ok {
					external = append(external, pomCoords{g, a, v})
					continue
				}
				sub, ext := x.managedVersions(bom, depth+1, visiting)
				for k, v := range sub {
					if _, set := table[k]; !set {
						table[k] = v
					}
				}
				external = append(external, ext...)
				continue
			}
			if _, set := table[g+":"+a]; set {
				continue
			}
			if v, ok := interpolate(m.version, props); ok && v != "" {
				table[g+":"+a] = v
			}
		}
	}
	return table, external
}

// unresolvedMaven is a declared dependency whose version the repository does
// not determine.
type unresolvedMaven struct {
	pomPath string
	name    string
	// source names where the version lives when it is outside the repository:
	// an external parent or imported BOM. Empty when nothing names it.
	source []pomCoords
}

// packages returns the packages a pom.xml declares at a version the
// repository determines, and the declared dependencies whose version it does
// not. Dependencies on the repository's own modules are neither: they are
// built here, not fetched.
func (x *mavenIndex) packages(p string) ([]Package, []unresolvedMaven, error) {
	f, ok := x.byPath[p]
	if !ok {
		return nil, nil, fmt.Errorf("pom.xml %s was not indexed", p)
	}
	if f.parseFail != nil {
		return nil, nil, f.parseFail
	}
	props := x.properties(f)
	managed, externalBOMs := x.managedVersions(f, 0, map[*pomFile]bool{})
	_, externalParent := x.chain(f)
	var sources []pomCoords
	if externalParent != nil {
		sources = append(sources, *externalParent)
	}
	sources = append(sources, externalBOMs...)

	type key struct{ name, ver string }
	seen := map[key]bool{}
	var pkgs []Package
	var unresolved []unresolvedMaven
	add := func(name, ver string) {
		k := key{name, ver}
		if seen[k] {
			return
		}
		seen[k] = true
		pkgs = append(pkgs, Package{Name: name, Version: ver, Ecosystem: "maven"})
	}
	for _, d := range f.deps {
		g, okG := interpolate(d.group, props)
		a, okA := interpolate(d.artifact, props)
		if !okG || !okA || g == "" || a == "" {
			continue
		}
		name := g + ":" + a
		if _, own := x.byGA[name]; own {
			continue
		}
		v := d.version
		if v == "" {
			v = managed[name]
		}
		if v != "" {
			if r, ok := interpolate(v, props); ok && r != "" {
				add(name, r)
				continue
			}
		}
		unresolved = append(unresolved, unresolvedMaven{pomPath: p, name: name, source: sources})
	}
	// dependencyManagement entries with a version the pom itself writes are
	// listed, as before: a BOM-style pom pins them. Imported BOMs and the
	// repository's own modules are not dependencies.
	for _, m := range f.managed {
		if m.scope == "import" || m.group == "" || m.artifact == "" || m.version == "" || strings.Contains(m.version, "${") {
			continue
		}
		name := m.group + ":" + m.artifact
		if _, own := x.byGA[name]; own {
			continue
		}
		add(name, m.version)
	}
	return pkgs, unresolved, nil
}

// parsePomXML reads one pom.xml on its own, as ParseLockfile does: properties
// it defines resolve, anything that needs another file does not.
func parsePomXML(content []byte) ([]Package, error) {
	x := newMavenIndex()
	x.add("pom.xml", content)
	pkgs, _, err := x.packages("pom.xml")
	return pkgs, err
}

// mavenDegradation summarises every unresolved Maven dependency of a scan in
// one degradation: a 124-module build must not produce 124 near-identical
// lines.
func mavenDegradation(all []unresolvedMaven) (detail, impact string) {
	poms := map[string]bool{}
	srcCount := map[string]int{}
	var examples []string
	for _, u := range all {
		poms[u.pomPath] = true
		for _, s := range u.source {
			srcCount[s.String()]++
		}
		if len(examples) < 3 {
			examples = append(examples, u.name+" ("+u.pomPath+")")
		}
	}
	files := "pom.xml file"
	if len(poms) != 1 {
		files = "pom.xml files"
	}
	detail = fmt.Sprintf("%d Maven dependencies in %d %s have no version nox can determine from this repository, e.g. %s",
		len(all), len(poms), files, strings.Join(examples, ", "))
	impact = "these dependencies were NOT checked for vulnerabilities"
	if len(srcCount) > 0 {
		srcs := make([]string, 0, len(srcCount))
		for s := range srcCount {
			srcs = append(srcs, s)
		}
		sort.Slice(srcs, func(i, j int) bool {
			if srcCount[srcs[i]] != srcCount[srcs[j]] {
				return srcCount[srcs[i]] > srcCount[srcs[j]]
			}
			return srcs[i] < srcs[j]
		})
		const shown = 3
		if len(srcs) > shown {
			srcs = append(srcs[:shown], fmt.Sprintf("%d more", len(srcCount)-shown))
		}
		impact += "; their versions are managed by " + strings.Join(srcs, ", ") + ", which is not in this repository"
	}
	return detail, impact
}
