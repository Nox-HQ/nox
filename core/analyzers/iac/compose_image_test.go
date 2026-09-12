package iac

import (
	"strings"
	"testing"
)

// A Compose service pinned to `latest` was reported by nothing.
//
// IAC-231 covered it by accident — a Kustomize rule that applied to every YAML
// file in the repository — and #637 removed that, which left
// chronos/test/integration/docker-compose.yml with no findings at all. The gap
// was named in that change's ledger entry rather than papered over.
//
// The reason this is a parse and not a pattern is in the fixture: Compose
// resolves shell-style substitutions before it reads an image reference, so a
// regex looking for `:latest` at the end of the value sees a `}`.

// composeFixture carries every form, pinned and not. Each service name says
// what it is for.
const composeFixture = `services:
  explicit_latest:
    image: nginx:latest
  default_is_latest:
    image: ${CHRONOS_IMAGE:-ghcr.io/klarlabs-studio/chronos:latest}
  substitution_in_the_middle:
    image: geerlingguy/docker-${MOLECULE_DISTRO:-rockylinux9}-ansible:latest
  no_tag_at_all:
    image: redis
  registry_port_is_not_a_tag:
    image: registry.local:5000/app
  pinned_version:
    image: nginx:1.25.3
  pinned_digest:
    image: nginx@sha256:aaaabbbbccccddddeeeeffff0000111122223333444455556666777788889999
  pinned_through_a_default:
    image: ${APP_IMAGE:-ghcr.io/acme/app:2.1.0}
  no_default_to_resolve:
    image: ${MUST_BE_SET}
  build_only:
    build: .
`

// TestComposeUnpinnedImages is both directions in one document. Five services
// are unpinned and five are not, and a rule that reported all ten would be as
// useless as one that reported none.
func TestComposeUnpinnedImages(t *testing.T) {
	fs := scanComposeImages("docker-compose.yml", []byte(composeFixture))
	got := map[string]string{}
	for _, f := range fs {
		got[f.Metadata["image"]] = f.Message
	}
	for _, want := range []string{
		"nginx:latest",
		"${CHRONOS_IMAGE:-ghcr.io/klarlabs-studio/chronos:latest}",
		"geerlingguy/docker-${MOLECULE_DISTRO:-rockylinux9}-ansible:latest",
		"redis",
		"registry.local:5000/app",
	} {
		if _, ok := got[want]; !ok {
			t.Errorf("%s is not pinned and was not reported", want)
		}
	}
	if n := len(fs); n != 5 {
		t.Errorf("reported %d services, want 5; got %v", n, got)
	}
}

// TestComposeResolvesTheSubstitutionInTheMessage. An operator reading
// "the `latest` tag" against a line that says `${CHRONOS_IMAGE:-…}` has to do
// the substitution in their head to check the finding. The message does it.
func TestComposeResolvesTheSubstitutionInTheMessage(t *testing.T) {
	fs := scanComposeImages("docker-compose.yml", []byte(composeFixture))
	var found bool
	for _, f := range fs {
		if f.Metadata["image"] != "${CHRONOS_IMAGE:-ghcr.io/klarlabs-studio/chronos:latest}" {
			continue
		}
		found = true
		if !strings.Contains(f.Message, "ghcr.io/klarlabs-studio/chronos:latest") {
			t.Errorf("the message does not name the reference the default resolves to: %s",
				f.Message)
		}
	}
	if !found {
		t.Fatal("the substitution-default service was not reported at all")
	}
}

// TestResolveComposeDefaults states the substitution rules directly.
//
// `:-` and `-` supply a default; `:?`, `?`, `:+` and `+` do not, and a
// reference with no default resolves to nothing this can speak about — which
// is why `complete` is a separate answer from the string.
func TestResolveComposeDefaults(t *testing.T) {
	for _, tc := range []struct {
		in       string
		want     string
		complete bool
	}{
		{"nginx:latest", "nginx:latest", true},
		{"${V:-nginx:latest}", "nginx:latest", true},
		{"${V-nginx:1.0}", "nginx:1.0", true},
		{"a-${V:-b}-c:latest", "a-b-c:latest", true},
		{"${OUTER:-${INNER:-nginx}}:1.0", "nginx:1.0", true},
		{"${V}", "", false},
		{"$V", "", false},
		{"${V:?required}", "", false},
		{"${V:+set}", "", false},
		{"${UNCLOSED:-x", "", false},
	} {
		got, complete := resolveComposeDefaults(tc.in)
		if complete != tc.complete {
			t.Errorf("resolveComposeDefaults(%q) complete = %v, want %v", tc.in, complete, tc.complete)
			continue
		}
		if complete && got != tc.want {
			t.Errorf("resolveComposeDefaults(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestImageTagIgnoresARegistryPort. `registry:5000/app` names a host and a
// port, so the last colon in a reference is not always a tag separator.
func TestImageTagIgnoresARegistryPort(t *testing.T) {
	for _, tc := range []struct {
		ref      string
		tag      string
		explicit bool
	}{
		{"nginx:1.25", "1.25", true},
		{"registry.local:5000/app", "", false},
		{"registry.local:5000/app:2.0", "2.0", true},
		{"redis", "", false},
		{"ghcr.io/acme/app:latest", "latest", true},
	} {
		tag, explicit := imageTag(tc.ref)
		if explicit != tc.explicit || (explicit && tag != tc.tag) {
			t.Errorf("imageTag(%q) = (%q, %v), want (%q, %v)", tc.ref, tag, explicit, tc.tag, tc.explicit)
		}
	}
}

// TestOnlyComposeFilesAreParsed. A Kubernetes manifest also has an `image:`,
// and reporting it here is how the rule this replaces went wrong in the first
// place.
func TestOnlyComposeFilesAreParsed(t *testing.T) {
	const manifest = `apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
        - name: web
          image: nginx:latest
`
	if fs := scanComposeImages("deployment.yaml", []byte(manifest)); len(fs) != 0 {
		t.Errorf("reported %d findings on a Kubernetes manifest", len(fs))
	}
	// And a file NAMED like a compose file but shaped like something else
	// produces nothing either, because the parse decides.
	if fs := scanComposeImages("docker-compose.yml", []byte(manifest)); len(fs) != 0 {
		t.Errorf("reported %d findings on a Deployment in a file named docker-compose.yml", len(fs))
	}
}

// TestTheComposeRuleIsPublished. It is evaluated by parsing and never handed to
// a matcher, so it lives in the analyzer's catalog set rather than the engine's.
// A finding whose rule ID resolves to nothing carries no remediation and
// appears in no `nox rules` listing.
func TestTheComposeRuleIsPublished(t *testing.T) {
	r, ok := NewAnalyzer().Rules().ByID(composeLatestRuleID)
	if !ok {
		t.Fatalf("%s is not in the published rule set", composeLatestRuleID)
	}
	if r.Remediation == "" {
		t.Errorf("%s carries no remediation", composeLatestRuleID)
	}
	if r.MatcherType != "" {
		t.Errorf("%s declares matcher_type %q; it is evaluated by parsing and must not "+
			"reach a matcher", composeLatestRuleID, r.MatcherType)
	}
}
