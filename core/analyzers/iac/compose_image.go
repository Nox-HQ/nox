package iac

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/rules/structural"
	"gopkg.in/yaml.v3"
)

// A Compose service pinned to `latest` is not reported by anything.
//
// IAC-231 covered it by accident — a Kustomize rule applying to every YAML file
// in the repository — and #637 removed that, which left
// chronos/test/integration/docker-compose.yml with no findings at all. The gap
// was named in that change's ledger entry rather than papered over; this closes
// it.
//
// It is not a regex, for a measured reason. Compose resolves shell-style
// substitutions before it reads an image reference, so the file that prompted
// this says
//
//	image: ${CHRONOS_IMAGE:-ghcr.io/klarlabs-studio/chronos:latest}
//
// and a pattern looking for `:latest` at the end of the value sees a `}`.
// geerlingguy/ansible-for-devops carries the other shape,
// `geerlingguy/docker-${MOLECULE_DISTRO:-rockylinux9}-ansible:latest`, where the
// substitution sits in the middle. The deps analyzer has the same blind spot
// from the other side: ParseDockerfile skips any FROM whose reference contains
// `$`, so a Dockerfile written that way produces no CONT-002 either.
//
// So the value is resolved the way Compose resolves it, and the reference is
// then parsed the way a registry parses it: digest wins over tag, a colon in
// the registry host is a port and not a tag separator, and no tag means
// `latest` by definition rather than by omission.

// composeLatestRuleID is the rule this file reports.
const composeLatestRuleID = "IAC-501"

// composeImageRule is registered in the rule set so the finding carries
// remediation text and `nox rules` lists it. It has no pattern: the analyzer
// evaluates it by parsing, the way CONT-001/002 are evaluated in the deps
// analyzer.
func composeImageRule() *rules.Rule {
	return &rules.Rule{
		ID:          composeLatestRuleID,
		Version:     "1.0",
		Description: "Docker Compose service image is not pinned to a version",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"iac", "docker-compose", "supply-chain"},
		Metadata:    map[string]string{"cwe": "CWE-829"},
		Remediation: "Pin the service image to an immutable reference: a specific version tag, or a digest (`image: nginx@sha256:…`). `latest` — written explicitly, left implicit, or reached through a `${VAR:-…}` default — is a moving target, so the container that runs in CI is not the one that was reviewed.",
		References:  []string{"https://cwe.mitre.org/data/definitions/829.html"},
	}
}

// isComposeFile reports whether path is a Compose file by name.
//
// The name is a discovery hint here and nothing more: services/image is a
// shape many YAML documents have, and the parse below confirms it. What the
// name decides is only which files are worth parsing twice.
func isComposeFile(path string) bool {
	base := strings.ToLower(filepath.Base(path))
	ext := filepath.Ext(base)
	if ext != ".yml" && ext != ".yaml" {
		return false
	}
	stem := strings.TrimSuffix(base, ext)
	return stem == "compose" || stem == "docker-compose" ||
		strings.HasPrefix(stem, "compose.") || strings.HasPrefix(stem, "docker-compose.")
}

// scanComposeImages reports every Compose service whose image is not pinned.
func scanComposeImages(path string, content []byte) []findings.Finding {
	if !isComposeFile(path) {
		return nil
	}
	docs, err := structural.Parse(content)
	if err != nil {
		// A document that does not parse is not a document this can speak
		// about. Saying nothing is correct; guessing with a regex is what this
		// exists to stop.
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
			image := mappingValue(spec, "image")
			if image == nil || image.Kind != yaml.ScalarNode {
				continue // A build-only service declares no image.
			}
			reason, unpinned := unpinnedImageReason(image.Value)
			if !unpinned {
				continue
			}
			out = append(out, findings.Finding{
				RuleID:     composeLatestRuleID,
				Severity:   findings.SeverityMedium,
				Confidence: findings.ConfidenceHigh,
				Message: fmt.Sprintf("Docker Compose service %q image is not pinned to a version: %s",
					name.Value, reason),
				Location: findings.Location{
					FilePath:    path,
					StartLine:   image.Line,
					EndLine:     image.Line,
					StartColumn: image.Column,
					EndColumn:   image.Column + len(image.Value),
				},
				Metadata: map[string]string{
					"cwe":   "CWE-829",
					"image": image.Value,
				},
			})
		}
	}
	return out
}

// mappingValue returns the value node for key in a mapping, following a
// document node to its content. Nil when the key is absent.
func mappingValue(n *yaml.Node, key string) *yaml.Node {
	if n == nil {
		return nil
	}
	if n.Kind == yaml.DocumentNode && len(n.Content) > 0 {
		n = n.Content[0]
	}
	if n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			return n.Content[i+1]
		}
	}
	return nil
}

// unpinnedImageReason reports whether an image reference is unpinned, and says
// which way.
//
// It returns false — reports nothing — whenever the reference still depends on
// a substitution with no default, because "the tag is whatever the environment
// says" is not a finding this can make. That is the same rule the rest of this
// package follows: a thing not established is not a thing to report.
func unpinnedImageReason(ref string) (string, bool) {
	resolved, complete := resolveComposeDefaults(ref)
	if !complete {
		return "", false
	}
	resolved = strings.TrimSpace(resolved)
	if resolved == "" {
		return "", false
	}
	if _, digest, ok := strings.Cut(resolved, "@"); ok && digest != "" {
		return "", false // Pinned to a digest, which is the strongest pin there is.
	}
	tag, explicit := imageTag(resolved)
	switch {
	case !explicit:
		return "no tag, which Docker resolves to `latest`", true
	case strings.EqualFold(tag, "latest"):
		if resolved != ref {
			return fmt.Sprintf("the `latest` tag, reached through a substitution default (%s)", resolved), true
		}
		return "the `latest` tag", true
	}
	return "", false
}

// imageTag splits the tag off a registry reference, and reports whether one was
// written at all.
//
// The last colon is not always a tag separator: `registry:5000/app` names a
// host and a port. A colon counts only when it comes after the final `/`.
func imageTag(ref string) (tag string, explicit bool) {
	lastSlash := strings.LastIndex(ref, "/")
	lastColon := strings.LastIndex(ref, ":")
	if lastColon <= lastSlash {
		return "", false
	}
	return ref[lastColon+1:], true
}

// resolveComposeDefaults substitutes `${VAR:-default}` and `${VAR-default}`
// with their defaults, the way Compose does before it reads the value.
//
// complete is false when any substitution remains that has no default, because
// the resulting string would then describe no image anyone runs.
func resolveComposeDefaults(ref string) (out string, complete bool) {
	var b strings.Builder
	complete = true
	for i := 0; i < len(ref); {
		if ref[i] != '$' {
			b.WriteByte(ref[i])
			i++
			continue
		}
		if i+1 >= len(ref) {
			b.WriteByte('$')
			break
		}
		if ref[i+1] != '{' {
			// `$VAR`: a bare reference, never a default.
			j := i + 1
			for j < len(ref) && (ref[j] == '_' ||
				(ref[j] >= 'a' && ref[j] <= 'z') || (ref[j] >= 'A' && ref[j] <= 'Z') ||
				(ref[j] >= '0' && ref[j] <= '9')) {
				j++
			}
			if j == i+1 {
				b.WriteByte('$')
				i++
				continue
			}
			return "", false
		}
		end := matchingBrace(ref, i+1)
		if end < 0 {
			return "", false
		}
		body := ref[i+2 : end]
		i = end + 1

		// `:-` and `-` introduce a default; `:?`, `?`, `:+` and `+` do not.
		var def string
		switch {
		case strings.Contains(body, ":-"):
			_, def, _ = strings.Cut(body, ":-")
		case strings.Contains(body, "-"):
			_, def, _ = strings.Cut(body, "-")
		default:
			return "", false
		}
		// A default may itself contain a substitution.
		inner, ok := resolveComposeDefaults(def)
		if !ok {
			return "", false
		}
		b.WriteString(inner)
	}
	return b.String(), complete
}

// matchingBrace returns the index of the `}` closing the `{` at open, or -1.
func matchingBrace(s string, open int) int {
	depth := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return i
			}
		}
	}
	return -1
}
