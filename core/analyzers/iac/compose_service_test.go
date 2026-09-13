package iac

import "testing"

// Three Compose rules asked what a service does NOT declare and spelled it with
// a negative lookahead RE2 does not implement, so none of them ever fired. They
// needed a per-SERVICE answer that names the service, which no absence span
// gives — so they are parsed now, per service.

const composeServices = `services:
  limited:
    image: nginx:1.25
    mem_limit: 512m
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost"]
    volumes:
      - ./conf:/etc/nginx/conf.d:ro
      - data:/var/lib/nginx
  swarm_limited:
    image: redis:7
    deploy:
      resources:
        limits:
          cpus: "0.5"
          memory: 256M
    healthcheck:
      test: ["CMD", "redis-cli", "ping"]
  unlimited:
    image: postgres:16
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock
      - ./data:/var/lib/postgresql/data
      - type: bind
        source: ./secrets
        target: /run/secrets
volumes:
  data:
`

// TestComposeServiceRulesAnswerPerService is the whole point of the rewrite:
// three services, and the answer differs per service and names it.
func TestComposeServiceRulesAnswerPerService(t *testing.T) {
	got := map[string][]string{}
	for _, f := range scanComposeServices("docker-compose.yml", []byte(composeServices)) {
		got[f.RuleID] = append(got[f.RuleID], f.Metadata["service"])
	}
	for _, tc := range []struct {
		rule  string
		want  []string
		claim string
	}{
		{"IAC-179", []string{"unlimited"}, "only the service with no mem_limit, no cpus and no deploy.resources.limits"},
		{"IAC-182", []string{"unlimited"}, "only the service with no healthcheck"},
		{"IAC-180", []string{"unlimited", "unlimited", "unlimited"}, "each writable bind mount, and not the :ro one or the named volume"},
	} {
		if len(got[tc.rule]) != len(tc.want) {
			t.Errorf("%s reported %v; want %s", tc.rule, got[tc.rule], tc.claim)
		}
		for _, svc := range got[tc.rule] {
			if svc != "unlimited" {
				t.Errorf("%s reported service %q, which declares what the rule asks for", tc.rule, svc)
			}
		}
	}
}

// TestANamedVolumeIsNotABindMount. `data:/var/lib/nginx` mounts a
// Docker-managed volume, not a host path — there is no host directory the
// container could reach through it, so read-only is not the question.
func TestANamedVolumeIsNotABindMount(t *testing.T) {
	const onlyNamed = `services:
  app:
    image: nginx:1.25
    mem_limit: 256m
    healthcheck:
      test: ["CMD", "true"]
    volumes:
      - data:/var/lib/nginx
volumes:
  data:
`
	for _, f := range scanComposeServices("docker-compose.yml", []byte(onlyNamed)) {
		if f.RuleID == "IAC-180" {
			t.Errorf("IAC-180 reported a named volume as a writable bind mount: %s", f.Message)
		}
	}
}

// TestBothResourceLimitSpellingsCount. Compose accepts `deploy.resources.limits`
// and the `mem_limit`/`cpus` shorthand, and they are not interchangeable across
// versions — so any one of them answers the question.
func TestBothResourceLimitSpellingsCount(t *testing.T) {
	for _, f := range scanComposeServices("docker-compose.yml", []byte(composeServices)) {
		if f.RuleID == "IAC-179" && f.Metadata["service"] == "swarm_limited" {
			t.Error("IAC-179 reported a service limited through deploy.resources.limits")
		}
	}
}
