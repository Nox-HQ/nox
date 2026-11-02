package deps

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
)

// fakeCentral answers from a fixed set of published POMs and records what it
// was asked.
type fakeCentral struct {
	poms    map[POMCoordinate]string
	down    bool
	batches [][]POMCoordinate
}

func (f *fakeCentral) FetchPOMs(_ context.Context, coords []POMCoordinate) ([]POMResult, error) {
	f.batches = append(f.batches, coords)
	if f.down {
		return nil, errors.New("NOX Intelligence answered HTTP 503")
	}
	out := make([]POMResult, 0, len(coords))
	for _, c := range coords {
		if p, ok := f.poms[c]; ok {
			out = append(out, POMResult{Coordinate: c, Status: POMFound, Content: []byte(p)})
			continue
		}
		out = append(out, POMResult{Coordinate: c, Status: POMNotFound})
	}
	return out, nil
}

func (f *fakeCentral) asked() []string {
	var out []string
	for _, b := range f.batches {
		for _, c := range b {
			out = append(out, c.Group+":"+c.Artifact+":"+c.Version)
		}
	}
	return out
}

// The shape of Spring Boot: the starter parent inherits from
// spring-boot-dependencies, which writes versions as properties and imports
// further BOMs (here Jackson's).
var springCentral = map[POMCoordinate]string{
	{"org.springframework.boot", "spring-boot-starter-parent", "4.1.0"}: pomHead + `
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId><version>4.1.0</version></parent>
  <artifactId>spring-boot-starter-parent</artifactId><packaging>pom</packaging></project>`,
	{"org.springframework.boot", "spring-boot-dependencies", "4.1.0"}: pomHead + `
  <groupId>org.springframework.boot</groupId><artifactId>spring-boot-dependencies</artifactId><version>4.1.0</version><packaging>pom</packaging>
  <properties><h2.version>2.1.214</h2.version><jackson-bom.version>2.15.0</jackson-bom.version></properties>
  <dependencyManagement><dependencies>` + dep("com.h2database", "h2", "${h2.version}") +
		dep("org.springframework.boot", "spring-boot-starter-web", "${project.version}") +
		`<dependency><groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>${jackson-bom.version}</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement></project>`,
	{"com.fasterxml.jackson", "jackson-bom", "2.15.0"}: pomHead + `
  <groupId>com.fasterxml.jackson</groupId><artifactId>jackson-bom</artifactId><version>2.15.0</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>` + dep("com.fasterxml.jackson.core", "jackson-databind", "2.15.0") +
		`</dependencies></dependencyManagement></project>`,
}

var petclinic = pomHead + `
  <parent><groupId>org.springframework.boot</groupId><artifactId>spring-boot-starter-parent</artifactId><version>4.1.0</version><relativePath/></parent>
  <groupId>org.example</groupId><artifactId>petclinic</artifactId><version>1.0</version>
  <dependencies>` + dep("com.h2database", "h2", "") + dep("com.fasterxml.jackson.core", "jackson-databind", "") +
	dep("org.springframework.boot", "spring-boot-starter-web", "") + `</dependencies></project>`

// The parent chain and the BOM it imports are fetched in waves (the starter
// parent names spring-boot-dependencies, which names jackson-bom) and every
// version resolves as it would from files in the repository, with no
// degradation. ${project.version} in inherited dependencyManagement is the
// child's version (1.0): Maven interpolates the assembled model, not each
// parent on its own. An imported BOM, by contrast, is interpolated by itself.
func TestMavenExternalParentChainIsFetchedAndResolved(t *testing.T) {
	src := &fakeCentral{poms: springCentral}
	got, degs := mavenPkgs(t, map[string]string{"pom.xml": petclinic}, WithPOMSource(src))
	want := []string{
		"com.fasterxml.jackson.core:jackson-databind@2.15.0",
		"com.h2database:h2@2.1.214",
		"org.springframework.boot:spring-boot-starter-web@1.0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
	if len(degs) != 0 {
		t.Errorf("degradations = %v, want none", degs)
	}
	if len(src.batches) != 3 {
		t.Errorf("waves = %d (%v), want 3: parent, its parent, the imported BOM", len(src.batches), src.asked())
	}
}

// The repository's own modules, and parents found in the repository, are never
// asked for: only what the tree cannot answer leaves the machine.
func TestMavenInRepoParentIsNeverFetched(t *testing.T) {
	src := &fakeCentral{poms: springCentral}
	mavenPkgs(t, map[string]string{
		"pom.xml": pomHead + `<groupId>com.example</groupId><artifactId>parent</artifactId><version>3.1</version>
  <properties><guava.version>29.0-jre</guava.version></properties></project>`,
		"core/pom.xml": pomHead + `<parent><groupId>com.example</groupId><artifactId>parent</artifactId><version>3.1</version></parent>
  <artifactId>core</artifactId><dependencies>` + dep("com.google.guava", "guava", "${guava.version}") + `</dependencies></project>`,
	}, WithPOMSource(src))
	if len(src.batches) != 0 {
		t.Errorf("asked for %v; an in-repo parent must not be fetched", src.asked())
	}
}

// A parent Central does not have (a company parent) stays unresolved, and the
// degradation says it is not on Central rather than "not in this repository".
func TestMavenParentNotOnCentralIsNamed(t *testing.T) {
	src := &fakeCentral{poms: springCentral}
	got, degs := mavenPkgs(t, map[string]string{"pom.xml": pomHead + `
  <parent><groupId>com.acme</groupId><artifactId>acme-parent</artifactId><version>7</version><relativePath/></parent>
  <artifactId>svc</artifactId><dependencies>` + dep("com.h2database", "h2", "") + `</dependencies></project>`,
	}, WithPOMSource(src))
	if len(got) != 0 {
		t.Errorf("packages = %v, want none", got)
	}
	if len(degs) != 1 || !strings.Contains(degs[0], "com.acme:acme-parent:7, which is not on Maven Central") {
		t.Errorf("degradations = %v", degs)
	}
}

// An unreachable source is not "no such file": the degradation names the
// failure and says a later scan may resolve it.
func TestMavenSourceDownIsNotNotFound(t *testing.T) {
	src := &fakeCentral{poms: springCentral, down: true}
	got, degs := mavenPkgs(t, map[string]string{"pom.xml": petclinic}, WithPOMSource(src))
	if len(got) != 0 {
		t.Errorf("packages = %v, want none", got)
	}
	if len(degs) != 1 || !strings.Contains(degs[0], "could not be fetched (NOX Intelligence answered HTTP 503)") ||
		strings.Contains(degs[0], "not on Maven Central") {
		t.Errorf("degradations = %v", degs)
	}
	if len(src.batches) != 1 {
		t.Errorf("waves = %d, want 1: a failed coordinate is not asked again in the same scan", len(src.batches))
	}
}

// Without a source (offline, or intelligence disabled) nothing is asked and
// the degradation says how the versions could be resolved.
func TestMavenWithoutSourceSaysHowToResolve(t *testing.T) {
	_, degs := mavenPkgs(t, map[string]string{"pom.xml": petclinic})
	if len(degs) != 1 || !strings.Contains(degs[0], "fetched only on an online scan with NOX Intelligence enabled") {
		t.Errorf("degradations = %v", degs)
	}
}

// A served file that is not the POM asked for resolves nothing: reading
// versions from the wrong file would be worse than reading none.
func TestMavenMismatchedPOMIsNotUsed(t *testing.T) {
	wrong := map[POMCoordinate]string{
		{"org.springframework.boot", "spring-boot-starter-parent", "4.1.0"}: springCentral[POMCoordinate{"com.fasterxml.jackson", "jackson-bom", "2.15.0"}],
	}
	src := &fakeCentral{poms: wrong}
	got, degs := mavenPkgs(t, map[string]string{"pom.xml": petclinic}, WithPOMSource(src))
	if len(got) != 0 || len(degs) != 1 || !strings.Contains(degs[0], "is not that POM") {
		t.Errorf("packages = %v, degradations = %v", got, degs)
	}
}

// A published parent that names itself, or a cycle across two, ends: each
// coordinate is asked for once.
func TestMavenRemoteParentCycleTerminates(t *testing.T) {
	src := &fakeCentral{poms: map[POMCoordinate]string{
		{"g", "a", "1"}: pomHead + `<parent><groupId>g</groupId><artifactId>b</artifactId><version>1</version></parent><artifactId>a</artifactId></project>`,
		{"g", "b", "1"}: pomHead + `<parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version></parent><artifactId>b</artifactId></project>`,
	}}
	mavenPkgs(t, map[string]string{"pom.xml": pomHead + `
  <parent><groupId>g</groupId><artifactId>a</artifactId><version>1</version><relativePath/></parent>
  <artifactId>svc</artifactId><dependencies>` + dep("x", "y", "") + `</dependencies></project>`,
	}, WithPOMSource(src))
	if asked := src.asked(); !slices.Equal(asked, []string{"g:a:1", "g:b:1"}) {
		t.Errorf("asked = %v, want each once", asked)
	}
}

// A BOM version that is still a ${...} reference cannot be asked for.
func TestMavenUninterpolatedCoordinateIsNotAsked(t *testing.T) {
	src := &fakeCentral{}
	mavenPkgs(t, map[string]string{"pom.xml": pomHead + `<groupId>g</groupId><artifactId>svc</artifactId><version>1</version>
  <dependencyManagement><dependencies><dependency><groupId>io.quarkus</groupId><artifactId>quarkus-bom</artifactId><version>${quarkus.version}</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
  <dependencies>` + dep("io.quarkus", "quarkus-rest", "") + `</dependencies></project>`,
	}, WithPOMSource(src))
	if len(src.batches) != 0 {
		t.Errorf("asked for %v", src.asked())
	}
}

// An imported BOM is interpolated in its own context, which includes its own
// parent: quarkus-amazon-services-bom writes ${awssdk.version}, defined in
// quarkus-amazon-services-parent. Found by the end-to-end run on
// quarkus-quickstarts: the BOM was fetched, its parent never asked for, and 18
// dependencies stayed unresolved.
func TestMavenFetchedBOMParentIsFetched(t *testing.T) {
	src := &fakeCentral{poms: map[POMCoordinate]string{
		{"io.qas", "qas-bom", "3.14.1"}: pomHead + `
  <parent><groupId>io.qas</groupId><artifactId>qas-parent</artifactId><version>3.14.1</version></parent>
  <artifactId>qas-bom</artifactId><packaging>pom</packaging>
  <dependencyManagement><dependencies>
    <dependency><groupId>software.amazon.awssdk</groupId><artifactId>bom</artifactId><version>${awssdk.version}</version><type>pom</type><scope>import</scope></dependency>
  </dependencies></dependencyManagement></project>`,
		{"io.qas", "qas-parent", "3.14.1"}: pomHead + `
  <groupId>io.qas</groupId><artifactId>qas-parent</artifactId><version>3.14.1</version><packaging>pom</packaging>
  <properties><awssdk.version>2.30.0</awssdk.version></properties></project>`,
		{"software.amazon.awssdk", "bom", "2.30.0"}: pomHead + `
  <groupId>software.amazon.awssdk</groupId><artifactId>bom</artifactId><version>2.30.0</version><packaging>pom</packaging>
  <dependencyManagement><dependencies>` + dep("software.amazon.awssdk", "netty-nio-client", "2.30.0") +
			`</dependencies></dependencyManagement></project>`,
	}}
	got, degs := mavenPkgs(t, map[string]string{"pom.xml": pomHead + `<groupId>g</groupId><artifactId>svc</artifactId><version>1</version>
  <dependencyManagement><dependencies><dependency><groupId>io.qas</groupId><artifactId>qas-bom</artifactId><version>3.14.1</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
  <dependencies>` + dep("software.amazon.awssdk", "netty-nio-client", "") + `</dependencies></project>`,
	}, WithPOMSource(src))
	if want := []string{"software.amazon.awssdk:netty-nio-client@2.30.0"}; !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v (asked %v)", got, want, src.asked())
	}
	if len(degs) != 0 {
		t.Errorf("degradations = %v", degs)
	}
}

// A published POM's parent is the published version it names, never the
// repository's module of the same groupId:artifactId: a company repository
// holding acme-parent 2.0 must not lend its properties to a published BOM that
// inherits from acme-parent 1.0.
func TestMavenFetchedPOMParentIsNotTheRepositoryModule(t *testing.T) {
	src := &fakeCentral{poms: map[POMCoordinate]string{
		{"com.acme", "acme-bom", "1.0"}: pomHead + `
  <parent><groupId>com.acme</groupId><artifactId>acme-parent</artifactId><version>1.0</version></parent>
  <artifactId>acme-bom</artifactId><packaging>pom</packaging>
  <dependencyManagement><dependencies>` + dep("org.lib", "lib", "${lib.version}") + `</dependencies></dependencyManagement></project>`,
		{"com.acme", "acme-parent", "1.0"}: pomHead + `
  <groupId>com.acme</groupId><artifactId>acme-parent</artifactId><version>1.0</version><packaging>pom</packaging>
  <properties><lib.version>1.0</lib.version></properties></project>`,
	}}
	got, _ := mavenPkgs(t, map[string]string{
		"parent/pom.xml": pomHead + `<groupId>com.acme</groupId><artifactId>acme-parent</artifactId><version>2.0</version><packaging>pom</packaging>
  <properties><lib.version>2.0</lib.version></properties></project>`,
		"svc/pom.xml": pomHead + `<groupId>com.acme</groupId><artifactId>svc</artifactId><version>2.0</version>
  <dependencyManagement><dependencies><dependency><groupId>com.acme</groupId><artifactId>acme-bom</artifactId><version>1.0</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
  <dependencies>` + dep("org.lib", "lib", "") + `</dependencies></project>`,
	}, WithPOMSource(src))
	if want := []string{"org.lib:lib@1.0"}; !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
}
