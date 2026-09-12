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

// `imagePullPolicy: Always` is not a finding. An unpinned image is.
//
// IAC-185 shipped as "Helm values or template uses Always image pull policy
// WITHOUT PINNED TAG" with the pattern
//
//	(?im)^image\s*:\s*\n?\s+pullPolicy\s*:\s*["']?Always["']?|imagePullPolicy\s*:\s*["']?Always["']?
//
// which never looks at a tag. Measured on kubernetes/examples it fired three
// times and two of the three images are pinned — `hazelcast-kubernetes:3.8_1`
// and `cassandra:v14` — so the rule was wrong by its own description on two
// thirds of what it reported. It also called all three "Helm values or
// template" while every one is a plain Kubernetes manifest, the wrong-family
// naming #636 and #637 exist to remove.
//
// Always is frequently the RIGHT setting: with a pinned digest it is harmless,
// and on a mutable tag it is what makes a rollout pick up a changed image.
// What deserves a finding is the pair — a pull policy that re-resolves the
// reference on every start, against a reference that can change underneath it.
// Deciding that means reading the container, which is why this is a parse
// rather than a pattern, like IAC-501.

// pullPolicyRuleID is the rule this file reports. It keeps IAC-185's ID so
// baselines, VEX statements and `nox:ignore` comments written against it go on
// resolving — the rule is corrected, not replaced.
const pullPolicyRuleID = "IAC-185"

// pullPolicyRule is registered for its metadata; the analyzer evaluates it by
// parsing. See the `catalog` field on Analyzer.
func pullPolicyRule() *rules.Rule {
	return &rules.Rule{
		ID:          pullPolicyRuleID,
		Version:     "2.0",
		Description: "Container pulls Always from an unpinned image reference",
		Severity:    findings.SeverityMedium,
		Confidence:  findings.ConfidenceHigh,
		Tags:        []string{"iac", "kubernetes", "supply-chain"},
		Metadata:    map[string]string{"cwe": "CWE-829"},
		Remediation: "Pin the image to a digest (`image: app@sha256:…`) or to an immutable version tag. `imagePullPolicy: Always` re-resolves the reference every time the container starts, so with a mutable tag the image that runs after a restart is not the image that was reviewed. Always is not itself the problem — pair it with a pinned reference and it is free.",
		References:  []string{"https://cwe.mitre.org/data/definitions/829.html"},
	}
}

// scanPullPolicies reports every Kubernetes container that sets
// `imagePullPolicy: Always` on an image reference that can change.
func scanPullPolicies(path string, content []byte) []findings.Finding {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml", ".json":
	default:
		return nil
	}
	docs, err := structural.Parse(content)
	if err != nil {
		return nil
	}
	var out []findings.Finding
	for _, res := range structural.Resources(docs) {
		if res.Family != structural.FamilyKubernetes {
			continue
		}
		for _, c := range containerNodes(res.Props) {
			image := mappingValue(c, "image")
			policy := mappingValue(c, "imagePullPolicy")
			if image == nil || policy == nil {
				continue
			}
			if !strings.EqualFold(strings.Trim(policy.Value, `"'`), "Always") {
				continue
			}
			reason, unpinned := unpinnedImageReason(image.Value)
			if !unpinned {
				continue
			}
			name := mappingValue(c, "name")
			who := "a container"
			if name != nil && name.Value != "" {
				who = fmt.Sprintf("container %q", name.Value)
			}
			out = append(out, findings.Finding{
				RuleID:     pullPolicyRuleID,
				Severity:   findings.SeverityMedium,
				Confidence: findings.ConfidenceHigh,
				Message: fmt.Sprintf("%s pulls Always from an unpinned image: %s",
					who, reason),
				Location: findings.Location{
					FilePath:    path,
					StartLine:   policy.Line,
					EndLine:     policy.Line,
					StartColumn: policy.Column,
					EndColumn:   policy.Column + len(policy.Value),
				},
				Metadata: map[string]string{"cwe": "CWE-829", "image": image.Value},
			})
		}
	}
	return out
}

// containerNodes returns every container mapping under a Kubernetes resource,
// wherever the kind puts its pod template.
//
// A Pod holds them at spec.containers; a Deployment, StatefulSet, DaemonSet,
// Job and ReplicaSet at spec.template.spec.containers; a CronJob one level
// deeper again. Rather than enumerate the kinds, this walks for any
// `containers` or `initContainers` sequence — the field name is the structure,
// and a kind added to Kubernetes tomorrow puts its containers under the same
// one.
func containerNodes(n *yaml.Node) []*yaml.Node {
	var out []*yaml.Node
	var walk func(*yaml.Node)
	walk = func(node *yaml.Node) {
		if node == nil {
			return
		}
		switch node.Kind {
		case yaml.DocumentNode, yaml.SequenceNode:
			for _, c := range node.Content {
				walk(c)
			}
		case yaml.MappingNode:
			for i := 0; i+1 < len(node.Content); i += 2 {
				k, v := node.Content[i], node.Content[i+1]
				if (k.Value == "containers" || k.Value == "initContainers") && v.Kind == yaml.SequenceNode {
					for _, c := range v.Content {
						if c.Kind == yaml.MappingNode {
							out = append(out, c)
						}
					}
					continue
				}
				walk(v)
			}
		}
	}
	walk(n)
	return out
}
