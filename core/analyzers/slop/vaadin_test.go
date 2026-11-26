package slop

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// slopPackages scans files (path -> body) as one project tree and returns the
// SLOP-001 packages reported, sorted.
func slopPackages(t *testing.T, files map[string]string) []string {
	t.Helper()
	dir := t.TempDir()
	var tree []discovery.Artifact
	for rel, body := range files {
		abs := filepath.Join(dir, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
		tree = append(tree, discovery.Artifact{Path: rel, AbsPath: abs, Type: discovery.Source})
	}
	fs, err := NewAnalyzer().ScanArtifactsInContext(context.Background(), tree, tree)
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range fs.Findings() {
		if f.RuleID == "SLOP-001" {
			got = append(got, f.Metadata["package"])
		}
	}
	slices.Sort(got)
	return got
}

// Vaadin writes frontend/generated/ itself on every build, and installs the
// npm packages of its components from the Java dependency: the package.json
// is generated too, and usually not committed. Neither the generated files'
// imports nor @vaadin/* and the Frontend/ alias in the project's own frontend
// code are undeclared dependencies of the project.
func TestVaadinFrontend(t *testing.T) {
	const gradle = "dependencies {\n    implementation 'com.vaadin:vaadin-spring-boot-starter'\n}\n"
	const pom = "<project><dependencies><dependency>\n<groupId>com.vaadin</groupId>\n<artifactId>vaadin-core</artifactId>\n</dependency></dependencies></project>\n"
	for _, c := range []struct {
		name  string
		files map[string]string
		want  []string
	}{
		{"generated tree skipped in a gradle Vaadin project", map[string]string{
			"build.gradle": gradle,
			"src/main/frontend/generated/flow/Flow.tsx":            "import '@vaadin/button';\nimport 'lit';\nimport 'leftpadd-xyz';\n",
			"src/main/frontend/generated/jar-resources/copilot.js": "import 'some-vaadin-internal';\n",
		}, nil},
		{"older layout, maven", map[string]string{
			"pom.xml":                      pom,
			"frontend/generated/index.tsx": "import 'Frontend/generated/routes.js';\nimport '@vaadin/router';\n",
		}, nil},
		{"project's own frontend code: @vaadin and Frontend/ declared, others still checked", map[string]string{
			"build.gradle.kts":                   "implementation(\"com.vaadin:vaadin-core\")\n",
			"src/main/frontend/views/contact.ts": "import '@vaadin/grid';\nimport { x } from 'Frontend/generated/endpoints.js';\nimport 'leftpadd-xyz';\n",
		}, []string{"leftpadd-xyz"}},
		// Not a Vaadin project: nothing changes.
		{"no Vaadin dependency", map[string]string{
			"build.gradle":                 "dependencies {\n    implementation 'org.springframework.boot:spring-boot-starter-web'\n}\n",
			"frontend/generated/client.ts": "import '@vaadin/button';\n",
		}, []string{"@vaadin/button"}},
		{"vaadin named only in a comment", map[string]string{
			"build.gradle":         "// we evaluated com.vaadin but chose React\n",
			"web/generated/app.ts": "import '@vaadin/button';\n",
		}, []string{"@vaadin/button"}},
		{"vaadin named in a README, not a build file", map[string]string{
			"README.md":                    "Add com.vaadin:vaadin-core to try the demo.\n",
			"frontend/generated/client.ts": "import '@vaadin/button';\n",
		}, []string{"@vaadin/button"}},
		{"Vaadin project, generated directory outside frontend/", map[string]string{
			"pom.xml":                 pom,
			"src/generated/client.ts": "import 'leftpadd-xyz';\n",
		}, []string{"leftpadd-xyz"}},
	} {
		if got := slopPackages(t, c.files); !slices.Equal(got, c.want) {
			t.Errorf("%s: SLOP-001 packages %q, want %q", c.name, got, c.want)
		}
	}
}
