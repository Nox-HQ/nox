package deps

import (
	"bytes"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// A Gradle dependency usually carries no version of its own: the Spring Boot
// plugin's dependency management, a platform() BOM or a version catalog
// supplies it, or the version is a $variable. Matching only
// group:artifact:version skipped all of those and said nothing, so a Spring
// Boot build looked like a project with three dependencies.
//
// Offline, nox resolves what the build file and its gradle.properties write
// down literally. The rest is reported, not guessed. A gradle.lockfile beside
// or above the build file pins every version, and governs it.

// reGradleCoord matches a string coordinate after a configuration name, with
// the version optional: implementation("g:a"), api 'g:a:1.0'. The group may
// not contain "(", so project(":core") and platform("…") are not matched.
var reGradleCoord = regexp.MustCompile(
	`(?:implementation|api|compile|compileOnly|runtimeOnly|testImplementation|testCompileOnly|testRuntimeOnly|classpath|annotationProcessor|kapt|ksp)\s*[\("']+([^:'"\s()]+):([^:'"\s()]+)(?::([^'")\s]+))?['"]`,
)

// reGradleVar matches a literal string variable: val x = "1.0", var x: String
// = "1.0", def x = '1.0', ext.x = "1.0", ext["x"] = "1.0", extra["x"] = "1.0",
// and the bare x = "1.0" of an ext { } block. A bare assignment elsewhere sets
// a project property of that name, which $x then also reads, so it is not
// confined to the block.
var reGradleVar = regexp.MustCompile(
	`^\s*(?:(?:val|var|def)\s+(\w+)(?:\s*:\s*String)?|ext\.(\w+)|(?:ext|extra)\[\s*["'](\w+)["']\s*\]|(\w+))\s*=\s*["']([^"'$]+)["']`,
)

// reGradleOwnVersion is a version that is the build's own: the artifact is
// built here, not fetched.
var reGradleOwnVersion = regexp.MustCompile(`^\$\{?(?:project\.)?version\}?$`)

// reGradleSpringBoot finds the Spring Boot plugin and its version, which names
// the BOM (spring-boot-dependencies) its dependency management applies.
var reGradleSpringBoot = regexp.MustCompile(`id\s*\(?\s*["']org\.springframework\.boot["']\s*\)?\s+version\s+["']([^"']+)["']`)

var reGradleRef = regexp.MustCompile(`\$\{?(\w+)\}?`)

// gradleBuild is what one build file declares.
type gradleBuild struct {
	pkgs []Package
	// unresolved lists group:artifact of declarations whose version nox could
	// not determine.
	unresolved []string
	// springBoot is the Spring Boot plugin version, when the plugin is applied.
	springBoot string
}

// parseGradleBuild reads a build file, resolving $variables from the file's
// own literal definitions and from props (its gradle.properties).
func parseGradleBuild(content []byte, props map[string]string) (gradleBuild, error) {
	var out gradleBuild
	vars := map[string]string{}
	for k, v := range props {
		vars[k] = v
	}
	sc := newLineScanner(bytes.NewReader(content))
	var lines []string
	for sc.Scan() {
		line := sc.Text()
		lines = append(lines, line)
		if m := reGradleVar.FindStringSubmatch(line); m != nil {
			vars[m[1]+m[2]+m[3]+m[4]] = m[5]
		}
		if m := reGradleSpringBoot.FindStringSubmatch(line); m != nil {
			out.springBoot = m[1]
		}
	}
	if err := sc.Err(); err != nil {
		return out, fmt.Errorf("scanning build.gradle: %w", err)
	}

	type key struct{ name, ver string }
	seen := map[key]bool{}
	missing := map[string]bool{}
	for _, line := range lines {
		for _, m := range reGradleCoord.FindAllStringSubmatch(line, -1) {
			name, ver := m[1]+":"+m[2], m[3]
			if reGradleOwnVersion.MatchString(ver) {
				continue
			}
			if strings.Contains(ver, "$") {
				ver = reGradleRef.ReplaceAllStringFunc(ver, func(ref string) string {
					if v, ok := vars[reGradleRef.FindStringSubmatch(ref)[1]]; ok {
						return v
					}
					return ref
				})
			}
			if ver == "" || strings.Contains(ver, "$") {
				if !missing[name] {
					missing[name] = true
					out.unresolved = append(out.unresolved, name)
				}
				continue
			}
			if k := (key{name, ver}); !seen[k] {
				seen[k] = true
				out.pkgs = append(out.pkgs, Package{Name: name, Version: ver, Ecosystem: "gradle"})
			}
		}
	}
	return out, nil
}

// parseBuildGradle reads one build file on its own, as ParseLockfile does.
func parseBuildGradle(content []byte) ([]Package, error) {
	b, err := parseGradleBuild(content, nil)
	return b.pkgs, err
}

// parseGradleProperties reads key=value (or key: value) lines; comments and
// blank lines are skipped.
func parseGradleProperties(content []byte) map[string]string {
	props := map[string]string{}
	for _, line := range strings.Split(string(content), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || line[0] == '#' || line[0] == '!' {
			continue
		}
		i := strings.IndexAny(line, "=:")
		if i <= 0 {
			continue
		}
		props[strings.TrimSpace(line[:i])] = strings.TrimSpace(line[i+1:])
	}
	return props
}

// unresolvedGradle is one build file's versionless declarations.
type unresolvedGradle struct {
	path       string
	names      []string
	springBoot string
}

// gradleDegradation summarises every versionless Gradle declaration of a scan
// in one degradation.
func gradleDegradation(all []unresolvedGradle) (detail, impact string) {
	n := 0
	var examples []string
	boot := map[string]bool{}
	for _, u := range all {
		n += len(u.names)
		for _, name := range u.names {
			if len(examples) < 3 {
				examples = append(examples, name+" ("+u.path+")")
			}
		}
		if u.springBoot != "" {
			boot[u.springBoot] = true
		}
	}
	files := "build file"
	if len(all) != 1 {
		files = "build files"
	}
	detail = fmt.Sprintf("%d Gradle dependencies in %d %s have no version nox can determine, e.g. %s",
		n, len(all), files, strings.Join(examples, ", "))
	impact = "these dependencies were NOT checked for vulnerabilities"
	if len(boot) > 0 {
		vs := make([]string, 0, len(boot))
		for v := range boot {
			vs = append(vs, v)
		}
		sort.Strings(vs)
		impact += "; their versions are managed by the Spring Boot plugin " + strings.Join(vs, ", ") +
			" (org.springframework.boot:spring-boot-dependencies), which nox does not resolve for Gradle"
	}
	impact += "; a gradle.lockfile (./gradlew dependencies --write-locks) pins every version and makes them checkable"
	return detail, impact
}

// governedBy reports whether a lockfile in one of lockDirs covers dir: the same
// directory or an ancestor, as manifestDedupe decides for manifests.
func governedBy(lockDirs []string, dir string) bool {
	for _, l := range lockDirs {
		if l == "." || l == dir || strings.HasPrefix(dir, l+"/") {
			return true
		}
	}
	return false
}
