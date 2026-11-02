package deps

import (
	"slices"
	"strings"
	"testing"
)

// A Maven dependency usually carries no literal version: Spring Boot, Quarkus
// and every multi-module build take it from a parent POM or an imported BOM,
// or write ${some.version}. Measured 2026-11-01, nox read 0 of 28 declared
// dependencies in spring-petclinic, 2 of 47 in WebGoat, 2 of 713 in dropwizard
// and 4 of 654 in quarkus-quickstarts, and recorded nothing about the rest: an
// online scan of spring-petclinic reported no vulnerable dependencies where
// osv-scanner, resolving the parent, reported 17.

func mavenPkgs(t *testing.T, files map[string]string, opts ...AnalyzerOption) (got, degs []string) {
	t.Helper()
	inv, d, _ := scanManifestTree(t, files, append([]AnalyzerOption{WithOSVDisabled()}, opts...)...)
	for _, p := range inv.Packages() {
		if p.Ecosystem == "maven" {
			got = append(got, p.Name+"@"+p.Version)
		}
	}
	// The inventory keeps one entry per declaring file (it is each finding's
	// location); the question here is which versions were determined.
	slices.Sort(got)
	got = slices.Compact(got)
	for _, it := range d.Items() {
		degs = append(degs, it.Detail+" || "+it.Impact)
	}
	return got, degs
}

const pomHead = `<?xml version="1.0"?>
<project xmlns="http://maven.apache.org/POM/4.0.0">
  <modelVersion>4.0.0</modelVersion>
`

func dep(g, a, v string) string {
	s := "<dependency><groupId>" + g + "</groupId><artifactId>" + a + "</artifactId>"
	if v != "" {
		s += "<version>" + v + "</version>"
	}
	return s + "</dependency>"
}

func TestMavenPropertyVersionIsResolved(t *testing.T) {
	got, degs := mavenPkgs(t, map[string]string{
		"pom.xml": pomHead + `<groupId>com.example</groupId><artifactId>app</artifactId><version>1.0</version>
  <properties><jackson.version>2.9.10</jackson.version><log4j.version>${log4j2.version}</log4j.version><log4j2.version>2.14.1</log4j2.version></properties>
  <dependencies>` + dep("com.fasterxml.jackson.core", "jackson-databind", "${jackson.version}") +
			dep("org.apache.logging.log4j", "log4j-core", "${log4j.version}") + `</dependencies></project>`,
	})
	want := []string{"com.fasterxml.jackson.core:jackson-databind@2.9.10", "org.apache.logging.log4j:log4j-core@2.14.1"}
	if !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
	if len(degs) != 0 {
		t.Errorf("degradations = %v, want none: every version was determined", degs)
	}
}

func TestMavenVersionFromInRepoParent(t *testing.T) {
	got, degs := mavenPkgs(t, map[string]string{
		"pom.xml": pomHead + `<groupId>com.example</groupId><artifactId>parent</artifactId><version>3.1</version><packaging>pom</packaging>
  <properties><guava.version>29.0-jre</guava.version></properties>
  <dependencyManagement><dependencies>` + dep("com.google.guava", "guava", "${guava.version}") +
			dep("commons-io", "commons-io", "2.6") + `</dependencies></dependencyManagement></project>`,
		"core/pom.xml": pomHead + `<parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>3.1</version></parent>
  <artifactId>core</artifactId>
  <dependencies>` + dep("com.google.guava", "guava", "") + dep("commons-io", "commons-io", "") +
			dep("com.example", "api", "${project.version}") + `</dependencies></project>`,
		"api/pom.xml": pomHead + `<parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>3.1</version></parent>
  <artifactId>api</artifactId></project>`,
	})
	// The parent's managed versions are in the inventory already (it lists
	// them); the child's guava and commons-io resolve to the same versions,
	// and com.example:api is the project's own module, not a dependency.
	want := []string{"com.google.guava:guava@29.0-jre", "commons-io:commons-io@2.6"}
	if !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
	if len(degs) != 0 {
		t.Errorf("degradations = %v, want none", degs)
	}
}

func TestMavenVersionFromInRepoImportedBOM(t *testing.T) {
	got, degs := mavenPkgs(t, map[string]string{
		"bom/pom.xml": pomHead + `<groupId>io.acme</groupId><artifactId>acme-bom</artifactId><version>2.0</version><packaging>pom</packaging>
  <properties><netty.version>4.1.42.Final</netty.version></properties>
  <dependencyManagement><dependencies>` + dep("io.netty", "netty-codec-http", "${netty.version}") + `</dependencies></dependencyManagement></project>`,
		"app/pom.xml": pomHead + `<groupId>io.acme</groupId><artifactId>app</artifactId><version>2.0</version>
  <dependencyManagement><dependencies><dependency><groupId>io.acme</groupId><artifactId>acme-bom</artifactId><version>2.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
  <dependencies>` + dep("io.netty", "netty-codec-http", "") + `</dependencies></project>`,
	})
	if !slices.Contains(got, "io.netty:netty-codec-http@4.1.42.Final") {
		t.Errorf("packages = %v, want netty-codec-http@4.1.42.Final from the in-repo BOM", got)
	}
	if slices.Contains(got, "io.acme:acme-bom@2.0") {
		t.Errorf("packages = %v: the project's own BOM is not a dependency", got)
	}
	if len(degs) != 0 {
		t.Errorf("degradations = %v, want none", degs)
	}
}

// The spring-petclinic shape: every version comes from a parent published to
// Maven Central. Nothing can be checked offline, and the scan must say so.
func TestMavenExternalParentIsReportedNotSilent(t *testing.T) {
	got, degs := mavenPkgs(t, map[string]string{
		"pom.xml": pomHead + `<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>4.1.0</version><relativePath/></parent>
  <groupId>org.springframework.samples</groupId><artifactId>spring-petclinic</artifactId><version>4.0.0-SNAPSHOT</version>
  <properties><webjars-locator.version>0.52</webjars-locator.version></properties>
  <dependencies>` + dep("org.springframework.boot", "spring-boot-starter-web", "") +
			dep("org.springframework.boot", "spring-boot-starter-data-jpa", "") +
			dep("org.webjars", "webjars-locator-lite", "${webjars-locator.version}") +
			dep("com.h2database", "h2", "${h2.version}") + `</dependencies></project>`,
	})
	if !slices.Equal(got, []string{"org.webjars:webjars-locator-lite@0.52"}) {
		t.Errorf("packages = %v, want only the locally versioned webjars-locator-lite", got)
	}
	if len(degs) != 1 {
		t.Fatalf("degradations = %v, want exactly one", degs)
	}
	for _, want := range []string{"3 Maven dependencies", "pom.xml", "org.springframework.boot:spring-boot-starter-parent:4.1.0", "NOT checked"} {
		if !strings.Contains(degs[0], want) {
			t.Errorf("degradation %q does not mention %q", degs[0], want)
		}
	}
}

func TestMavenExternalImportedBOMIsNamed(t *testing.T) {
	_, degs := mavenPkgs(t, map[string]string{
		"pom.xml": pomHead + `<groupId>org.acme</groupId><artifactId>q</artifactId><version>1.0</version>
  <dependencyManagement><dependencies><dependency><groupId>io.quarkus.platform</groupId><artifactId>quarkus-bom</artifactId><version>3.15.1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
  <dependencies>` + dep("io.quarkus", "quarkus-rest", "") + `</dependencies></project>`,
	})
	if len(degs) != 1 || !strings.Contains(degs[0], "io.quarkus.platform:quarkus-bom:3.15.1") {
		t.Errorf("degradations = %v, want one naming the imported quarkus-bom", degs)
	}
}

// One degradation for the whole scan, however many modules: quarkus-quickstarts
// has 124 pom.xml files and must not produce 124 near-identical lines.
func TestMavenUnresolvedIsOneDegradationAcrossModules(t *testing.T) {
	files := map[string]string{}
	for _, m := range []string{"a", "b", "c", "d", "e", "f", "g"} {
		files[m+"/pom.xml"] = pomHead + `<parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>3.3.0</version></parent>
  <groupId>x</groupId><artifactId>` + m + `</artifactId><version>1</version>
  <dependencies>` + dep("org.springframework.boot", "spring-boot-starter-web", "") + `</dependencies></project>`
	}
	_, degs := mavenPkgs(t, files)
	if len(degs) != 1 || !strings.Contains(degs[0], "7 Maven dependencies") || !strings.Contains(degs[0], "7 pom.xml") {
		t.Errorf("degradations = %v, want one covering 7 dependencies in 7 pom.xml files", degs)
	}
}

// A parent that is in the repository but not at the default ../pom.xml is
// found by its coordinates; a relativePath pointing elsewhere is followed.
func TestMavenParentFoundByCoordinatesOrRelativePath(t *testing.T) {
	got, degs := mavenPkgs(t, map[string]string{
		"build/parent/pom.xml": pomHead + `<groupId>g</groupId><artifactId>p</artifactId><version>1</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>` + dep("org.yaml", "snakeyaml", "1.26") + `</dependencies></dependencyManagement></project>`,
		"mods/one/pom.xml": pomHead + `<parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version><relativePath>../../build/parent/pom.xml</relativePath></parent>
  <artifactId>one</artifactId><dependencies>` + dep("org.yaml", "snakeyaml", "") + `</dependencies></project>`,
		"mods/two/pom.xml": pomHead + `<parent><groupId>g</groupId><artifactId>p</artifactId><version>1</version></parent>
  <artifactId>two</artifactId><dependencies>` + dep("org.yaml", "snakeyaml", "") + `</dependencies></project>`,
	})
	if !slices.Equal(got, []string{"org.yaml:snakeyaml@1.26"}) {
		t.Errorf("packages = %v, want snakeyaml@1.26", got)
	}
	if len(degs) != 0 {
		t.Errorf("degradations = %v, want none", degs)
	}
}

// A parent cycle (malformed, but files are untrusted) terminates.
func TestMavenParentCycleTerminates(t *testing.T) {
	_, degs := mavenPkgs(t, map[string]string{
		"a/pom.xml": pomHead + `<parent><groupId>g</groupId><artifactId>b</artifactId><version>1</version><relativePath>../b/pom.xml</relativePath></parent><artifactId>a</artifactId>
  <dependencies>` + dep("x", "y", "") + `</dependencies></project>`,
		"b/pom.xml": pomHead + `<parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version><relativePath>../a/pom.xml</relativePath></parent><artifactId>b</artifactId></project>`,
	})
	if len(degs) != 1 {
		t.Errorf("degradations = %v, want one for x:y", degs)
	}
}

// The quarkus-quickstarts shape: the root pom.xml is an aggregator listing
// modules, and each module's parent is a different pom. ../pom.xml exists but
// is not the parent, so its dependencyManagement must not supply versions.
func TestMavenAggregatorAtRelativePathIsNotTheParent(t *testing.T) {
	got, degs := mavenPkgs(t, map[string]string{
		"pom.xml": pomHead + `<groupId>org.acme</groupId><artifactId>aggregator</artifactId><version>1</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>` + dep("io.netty", "netty-codec-http", "4.1.42.Final") + `</dependencies></dependencyManagement></project>`,
		"m/pom.xml": pomHead + `<parent><groupId>io.quarkus</groupId><artifactId>quarkus-parent</artifactId><version>3.15.1</version></parent>
  <artifactId>m</artifactId><dependencies>` + dep("io.netty", "netty-codec-http", "") + `</dependencies></project>`,
	})
	if len(degs) != 1 || !strings.Contains(degs[0], "io.quarkus:quarkus-parent:3.15.1") {
		t.Errorf("degradations = %v, want netty unresolved, managed by the external quarkus-parent", degs)
	}
	// The aggregator lists its own managed version; the module adds nothing.
	if !slices.Equal(got, []string{"io.netty:netty-codec-http@4.1.42.Final"}) {
		t.Errorf("packages = %v", got)
	}
}

// An imported BOM is a table of versions, not code the build ships.
func TestMavenImportedBOMIsNotAPackage(t *testing.T) {
	got, _ := mavenPkgs(t, map[string]string{
		"pom.xml": pomHead + `<groupId>org.acme</groupId><artifactId>q</artifactId><version>1.0</version>
  <dependencyManagement><dependencies><dependency><groupId>io.quarkus.platform</groupId><artifactId>quarkus-bom</artifactId><version>3.15.1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement></project>`,
	})
	if len(got) != 0 {
		t.Errorf("packages = %v, want none", got)
	}
}
