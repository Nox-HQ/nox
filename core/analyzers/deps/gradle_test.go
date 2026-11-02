package deps

import (
	"slices"
	"strings"
	"testing"
)

// A Gradle dependency usually has no version of its own: the Spring Boot
// plugin's dependency management, a platform() BOM or a version catalog
// supplies it. The parser matched only group:artifact:version, so on
// spring-petclinic-kotlin about 20 of 23 declared dependencies were skipped
// with no degradation, and $variable versions were skipped the same way.

func gradlePkgs(t *testing.T, files map[string]string) (got, degs []string) {
	t.Helper()
	inv, d, _ := scanManifestTree(t, files, WithOSVDisabled())
	for _, p := range inv.Packages() {
		if p.Ecosystem == "gradle" {
			got = append(got, p.Name+"@"+p.Version)
		}
	}
	slices.Sort(got)
	got = slices.Compact(got)
	for _, it := range d.Items() {
		degs = append(degs, it.Detail+" || "+it.Impact)
	}
	return got, degs
}

const kotlinBuild = `plugins {
    id("org.springframework.boot") version "4.1.2"
    id("io.spring.dependency-management") version "1.1.7"
}

val boostrapVersion = "5.3.8"
val fontAwesomeVersion: String = "4.7.0"

dependencies {
    implementation("org.springframework.boot:spring-boot-starter-actuator")
    implementation("org.webjars.npm:bootstrap:$boostrapVersion")
    implementation("org.webjars.npm:font-awesome:${fontAwesomeVersion}")
    runtimeOnly("com.h2database:h2")
    implementation(project(":core"))
    implementation(platform("org.springframework.boot:spring-boot-dependencies:4.1.2"))
    implementation(libs.guava)
    testImplementation("org.junit.jupiter:junit-jupiter-api:5.10.0")
}
`

func TestGradleVariablesResolveAndVersionlessIsReported(t *testing.T) {
	got, degs := gradlePkgs(t, map[string]string{"build.gradle.kts": kotlinBuild})
	want := []string{
		"org.junit.jupiter:junit-jupiter-api@5.10.0",
		"org.webjars.npm:bootstrap@5.3.8",
		"org.webjars.npm:font-awesome@4.7.0",
	}
	if !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
	if len(degs) != 1 {
		t.Fatalf("degradations = %v, want one", degs)
	}
	for _, s := range []string{
		"2 Gradle dependencies in 1 build file have no version nox can determine",
		"org.springframework.boot:spring-boot-starter-actuator (build.gradle.kts)",
		"NOT checked",
		"Spring Boot plugin 4.1.2",
		"gradle.lockfile",
	} {
		if !strings.Contains(degs[0], s) {
			t.Errorf("degradation lacks %q: %s", s, degs[0])
		}
	}
	// A project reference, a platform BOM and a catalog alias are not
	// dependencies with a missing version.
	detail, _, _ := strings.Cut(degs[0], " || ")
	for _, s := range []string{"project(", "spring-boot-dependencies", "libs."} {
		if strings.Contains(detail, s) {
			t.Errorf("degradation counts %q: %s", s, detail)
		}
	}
}

func TestGradlePropertiesFileResolvesVersions(t *testing.T) {
	got, degs := gradlePkgs(t, map[string]string{
		"app/build.gradle": `ext.jacksonVersion = '2.9.10'
dependencies {
    implementation "com.fasterxml.jackson.core:jackson-databind:$jacksonVersion"
    implementation 'org.apache.logging.log4j:log4j-core:${log4jVersion}'
}`,
		"app/gradle.properties": "# versions\nlog4jVersion=2.14.1\n",
	})
	want := []string{"com.fasterxml.jackson.core:jackson-databind@2.9.10", "org.apache.logging.log4j:log4j-core@2.14.1"}
	if !slices.Equal(got, want) {
		t.Errorf("packages = %v, want %v", got, want)
	}
	if len(degs) != 0 {
		t.Errorf("degradations = %v, want none", degs)
	}
}

// A variable defined nowhere nox reads (a root project's ext block) is
// reported, not dropped.
func TestGradleUndefinedVariableIsReported(t *testing.T) {
	_, degs := gradlePkgs(t, map[string]string{
		"build.gradle": `dependencies { implementation "com.google.guava:guava:$guavaVersion" }`,
	})
	if len(degs) != 1 || !strings.Contains(degs[0], "com.google.guava:guava") {
		t.Errorf("degradations = %v", degs)
	}
}

// A gradle.lockfile beside or above the build file pins every resolved
// version, so a versionless declaration there is not a gap.
func TestGradleLockfileGovernsVersionless(t *testing.T) {
	_, degs := gradlePkgs(t, map[string]string{
		"build.gradle.kts": kotlinBuild,
		"gradle.lockfile":  "org.springframework.boot:spring-boot-starter-actuator:4.1.2=runtimeClasspath\ncom.h2database:h2:2.3.232=runtimeClasspath\nempty=\n",
	})
	if len(degs) != 0 {
		t.Errorf("degradations = %v, want none: the lockfile pins them", degs)
	}
}

// RxJava writes its versions in an ext { } block as bare assignments.
func TestGradleExtBlockAssignmentsResolve(t *testing.T) {
	got, degs := gradlePkgs(t, map[string]string{"build.gradle": `ext {
    mockitoVersion = "5.23.0"
    guavaVersion = '33.7.2-jre'
}
dependencies {
    testImplementation "org.mockito:mockito-core:$mockitoVersion"
    implementation "com.google.guava:guava:${guavaVersion}"
}`})
	want := []string{"com.google.guava:guava@33.7.2-jre", "org.mockito:mockito-core@5.23.0"}
	if !slices.Equal(got, want) || len(degs) != 0 {
		t.Errorf("packages = %v, degradations = %v; want %v and none", got, degs, want)
	}
}

// A declaration at ${project.version} is the build's own artifact (okhttp-bom
// constrains okhttp-jvm to the version being built): not a dependency to
// check, and not a gap.
func TestGradleProjectVersionIsTheBuildsOwnArtifact(t *testing.T) {
	got, degs := gradlePkgs(t, map[string]string{"okhttp-bom/build.gradle.kts": `dependencies {
  constraints {
    api("com.squareup.okhttp3:okhttp-jvm:${project.version}")
    api("com.squareup.okhttp3:logging-interceptor:$version")
  }
}`})
	if len(got) != 0 || len(degs) != 0 {
		t.Errorf("packages = %v, degradations = %v; want neither", got, degs)
	}
}
