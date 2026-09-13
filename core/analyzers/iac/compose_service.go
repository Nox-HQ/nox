package iac

import (
	"fmt"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/rules/structural"
	"gopkg.in/yaml.v3"
)

// Three Compose rules asked what a service does NOT declare, and spelled it
// with a negative lookahead:
//
//	IAC-179  (?i)(services|version)\s*:(?:[^}](?!deploy\s*:\s*\n\s+resources|mem_limit|cpus))*
//	IAC-180  (?i)volumes\s*:\s*\n(\s+-\s+(?!.*:ro\b|.*:readonly\b|.*read_only).*:\s*/[^\n]*\n)+
//	IAC-182  (?i)(services\s*:\s*\n\s+\w+\s*:\s*\n(?:[^}](?!healthcheck))*){1}
//
// RE2 has no lookahead. All three failed to compile, RegexMatcher.compile
// returned the error, Match answered nil, and the rules loaded, listed in
// `nox rules`, ran on every Compose file and matched nothing.
//
// The absence matcher is the usual answer, but not here: each question is about
// ONE SERVICE and the answer has to name it. A yaml-block span anchored on
// `services:` covers every service at once, so one unlimited service would
// silence the rule for all of them, and the finding could not say which. The
// parse that IAC-501 already does over services/<name> answers per service and
// points at the line.
//
// Their IDs are kept. Baselines hash the rule ID, and VEX statements and
// `nox:ignore` comments name it directly, so these are corrected rather than
// replaced.

// composeServiceRules are the three, registered for their metadata; the
// analyzer evaluates them by parsing. See the `catalog` field on Analyzer.
func composeServiceRules() []*rules.Rule {
	return []*rules.Rule{
		{
			ID:          "IAC-179",
			Version:     "2.0",
			Description: "Docker Compose service declares no resource limits",
			Severity:    findings.SeverityMedium,
			Confidence:  findings.ConfidenceHigh,
			Tags:        []string{"iac", "docker-compose", "resources"},
			Metadata:    map[string]string{"cwe": "CWE-770"},
			Remediation: "Give the service a memory and CPU ceiling — `deploy.resources.limits` under Swarm, or the `mem_limit`/`cpus` shorthand Compose accepts directly. A container with no limit can take the host down with it.",
			References:  []string{"https://cwe.mitre.org/data/definitions/770.html"},
		},
		{
			ID:          "IAC-180",
			Version:     "2.0",
			Description: "Docker Compose bind mount is writable",
			Severity:    findings.SeverityMedium,
			Confidence:  findings.ConfidenceHigh,
			Tags:        []string{"iac", "docker-compose", "filesystem"},
			Metadata:    map[string]string{"cwe": "CWE-732"},
			Remediation: "Append `:ro` to the mount, or set `read_only: true` on the long-form entry. A writable bind mount lets the container modify the host path it was given, which is rarely what a config or socket mount intends.",
			References:  []string{"https://cwe.mitre.org/data/definitions/732.html"},
		},
		{
			ID:          "IAC-182",
			Version:     "2.0",
			Description: "Docker Compose service declares no health check",
			Severity:    findings.SeverityLow,
			Confidence:  findings.ConfidenceHigh,
			Tags:        []string{"iac", "docker-compose", "availability"},
			Metadata:    map[string]string{"cwe": "CWE-693"},
			Remediation: "Add a `healthcheck:` to the service, or inherit one from the image. Without it Compose calls a container healthy as soon as the process starts, so `depends_on: service_healthy` waits for nothing and a wedged process is never restarted.",
			References:  []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
	}
}

// scanComposeServices evaluates the three per-service absence rules.
func scanComposeServices(path string, content []byte) []findings.Finding {
	if !isComposeFile(path) {
		return nil
	}
	docs, err := structural.Parse(content)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	for _, doc := range docs {
		services := mappingValue(doc, "services")
		if services == nil || services.Kind != yaml.MappingNode {
			continue
		}
		for i := 0; i+1 < len(services.Content); i += 2 {
			name, spec := services.Content[i], services.Content[i+1]
			if spec.Kind != yaml.MappingNode {
				continue
			}
			out = append(out, composeServiceFindings(path, name, spec)...)
		}
	}
	return out
}

// composeServiceFindings evaluates one service.
func composeServiceFindings(path string, name, spec *yaml.Node) []findings.Finding {
	var out []findings.Finding
	at := func(id, msg string, sev findings.Severity, n *yaml.Node) findings.Finding {
		return findings.Finding{
			RuleID: id, Severity: sev, Confidence: findings.ConfidenceHigh,
			Message: fmt.Sprintf("Docker Compose service %q %s", name.Value, msg),
			Location: findings.Location{
				FilePath: path, StartLine: n.Line, EndLine: n.Line,
				StartColumn: n.Column, EndColumn: n.Column + len(n.Value),
			},
			Metadata: map[string]string{"service": name.Value},
		}
	}

	// IAC-179: a memory or CPU ceiling, in either spelling Compose accepts.
	if !hasResourceLimit(spec) {
		out = append(out, at("IAC-179", "declares no resource limits: no `deploy.resources.limits`, "+
			"no `mem_limit` and no `cpus`", findings.SeverityMedium, name))
	}
	// IAC-182: a health check, or `healthcheck: disable` which is a deliberate
	// statement rather than an omission.
	if mappingValue(spec, "healthcheck") == nil {
		out = append(out, at("IAC-182", "declares no health check, so Compose calls it healthy "+
			"as soon as the process starts", findings.SeverityLow, name))
	}
	// IAC-180: every writable bind mount, reported where it is written.
	for _, v := range writableBindMounts(spec) {
		// The short form's node value is the whole `SOURCE:TARGET[:MODE]`
		// entry; the message names the source, which is the host path the
		// finding is about.
		source, _, _ := strings.Cut(v.Value, ":")
		out = append(out, findings.Finding{
			RuleID: "IAC-180", Severity: findings.SeverityMedium, Confidence: findings.ConfidenceHigh,
			Message: fmt.Sprintf("Docker Compose service %q mounts host path %q writable",
				name.Value, source),
			Location: findings.Location{
				FilePath: path, StartLine: v.Line, EndLine: v.Line,
				StartColumn: v.Column, EndColumn: v.Column + len(v.Value),
			},
			Metadata: map[string]string{"service": name.Value, "mount": source},
		})
	}
	return out
}

// hasResourceLimit reports whether a service declares any memory or CPU ceiling.
//
// Compose accepts three spellings and they are not interchangeable across
// versions: `deploy.resources.limits` (Swarm and Compose v2), and the
// `mem_limit` / `cpus` shorthands. Any one of them is a limit, so any one of
// them answers the question.
func hasResourceLimit(spec *yaml.Node) bool {
	for _, k := range []string{"mem_limit", "cpus", "memswap_limit", "cpu_quota"} {
		if mappingValue(spec, k) != nil {
			return true
		}
	}
	limits := mappingValue(mappingValue(mappingValue(spec, "deploy"), "resources"), "limits")
	return limits != nil && len(limits.Content) > 0
}

// writableBindMounts returns the volume entries that mount a HOST PATH without
// a read-only flag.
//
// A named volume (`data:/var/lib/db`) is not a bind mount and is excluded: the
// source is Docker-managed, not a path on the host the container could reach
// through it. A bind mount is the one whose source is a path — absolute,
// relative, or `~`.
func writableBindMounts(spec *yaml.Node) []*yaml.Node {
	vols := mappingValue(spec, "volumes")
	if vols == nil || vols.Kind != yaml.SequenceNode {
		return nil
	}
	var out []*yaml.Node
	for _, v := range vols.Content {
		switch v.Kind {
		case yaml.ScalarNode:
			// Short form: SOURCE:TARGET[:MODE].
			parts := strings.Split(v.Value, ":")
			if len(parts) < 2 || !isHostPath(parts[0]) {
				continue
			}
			mode := ""
			if len(parts) > 2 {
				mode = strings.ToLower(parts[len(parts)-1])
			}
			if mode != "ro" && mode != "readonly" {
				out = append(out, v)
			}
		case yaml.MappingNode:
			// Long form: {type, source, target, read_only}.
			if t := mappingValue(v, "type"); t != nil && t.Value != "bind" {
				continue
			}
			src := mappingValue(v, "source")
			if src == nil || !isHostPath(src.Value) {
				continue
			}
			if ro := mappingValue(v, "read_only"); ro != nil && strings.EqualFold(ro.Value, "true") {
				continue
			}
			out = append(out, src)
		}
	}
	return out
}

// isHostPath reports whether a volume source names a path rather than a named
// volume.
func isHostPath(s string) bool {
	return strings.HasPrefix(s, "/") || strings.HasPrefix(s, "./") ||
		strings.HasPrefix(s, "../") || strings.HasPrefix(s, "~") ||
		strings.HasPrefix(s, "${") || strings.HasPrefix(s, "$")
}
