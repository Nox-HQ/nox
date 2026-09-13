package deps

import "testing"

// A Dockerfile build-stage reference is not a base image.
//
// ParseDockerfile skipped `scratch` and `${VAR}` references but tracked no
// stage names, so in
//
//	FROM python:3.14-alpine3.23 AS certbot
//	…
//	FROM certbot AS certbot-plugin
//
// the second FROM produced a container component called "certbot" at version
// "latest". Measured on certbot@2b817be1: a dependency the project does not
// have, in the CycloneDX and SPDX documents downstream consumers trust, and a
// name handed to OSV where it can match an advisory for an unrelated image.
// CONT-001 and CONT-002 reported it too, which is how it was noticed — but the
// SBOM was the serious half.

const multiStageDockerfile = `FROM python:3.14-alpine3.23 AS certbot
RUN pip install certbot
FROM scratch
FROM ${BASE_IMAGE}
FROM certbot AS certbot-plugin
COPY --from=certbot /opt /opt
FROM CERTBOT AS case-insensitive
FROM redis:7 AS cache
`

// TestABuildStageIsNotAComponent is the whole point: the SBOM must contain the
// images this Dockerfile pulls, and nothing else.
func TestABuildStageIsNotAComponent(t *testing.T) {
	pkgs, err := ParseDockerfile([]byte(multiStageDockerfile))
	if err != nil {
		t.Fatalf("ParseDockerfile: %v", err)
	}
	got := map[string]string{}
	for _, p := range pkgs {
		got[p.Name] = p.Version
	}
	want := map[string]string{
		"python": "3.14-alpine3.23",
		"redis":  "7",
	}
	if len(got) != len(want) {
		t.Errorf("components = %v, want %v", got, want)
	}
	for n, v := range want {
		if got[n] != v {
			t.Errorf("component %s = %q, want %q", n, got[n], v)
		}
	}
	if _, ok := got["certbot"]; ok {
		t.Error("the build stage `certbot` is in the SBOM as a component; it is a stage of " +
			"this build, not an image anyone publishes")
	}
}

// TestStageNamesAreCaseInsensitive. Docker treats them so, and the fixture
// above references the stage as `CERTBOT` on purpose.
func TestStageNamesAreCaseInsensitive(t *testing.T) {
	pkgs, _ := ParseDockerfile([]byte(multiStageDockerfile))
	for _, p := range pkgs {
		if p.Name == "CERTBOT" || p.Name == "certbot" {
			t.Errorf("a stage referenced as %q was treated as an image", p.Name)
		}
	}
}

// TestTheTwoWalksStayAligned. dockerfileFromLines and ParseDockerfile are
// index-aligned — fromLines[i] is the line of packages[i] — and they used to
// carry two copies of the skip logic. A skip added to one and not the other
// attaches every later finding to the wrong line, silently.
func TestTheTwoWalksStayAligned(t *testing.T) {
	pkgs, err := ParseDockerfile([]byte(multiStageDockerfile))
	if err != nil {
		t.Fatalf("ParseDockerfile: %v", err)
	}
	lines := dockerfileFromLines([]byte(multiStageDockerfile))
	if len(lines) != len(pkgs) {
		t.Fatalf("%d packages but %d line numbers; every finding after the first "+
			"divergence lands on the wrong line", len(pkgs), len(lines))
	}
	// And they must be the RIGHT lines: python on 1, redis on 8.
	if len(lines) == 2 && (lines[0] != 1 || lines[1] != 8) {
		t.Errorf("line numbers = %v, want [1 8]", lines)
	}
}

// TestScratchIsStillSkipped guards the case that was already handled, so a
// refactor of the shared predicate cannot quietly drop it.
func TestScratchIsStillSkipped(t *testing.T) {
	pkgs, _ := ParseDockerfile([]byte("FROM scratch\nCOPY app /app\n"))
	if len(pkgs) != 0 {
		t.Errorf("scratch produced %d components; it is Docker's empty pseudo-image", len(pkgs))
	}
}
