package iac

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules/structural"
)

// IAC-296 nominates every Ingress (its pattern is `kind: Ingress`); this
// refiner keeps the nomination only when the document establishes the claim
// the rule makes:
//
//	the Ingress HAS a tls block, and either
//	  (a) a host in spec.rules[].host is covered by no spec.tls[].hosts entry
//	      (that host is served without TLS), or
//	  (b) a tls entry has no secretName and nothing annotates a certificate
//	      source (cert-manager and similar).
//
// An Ingress with no tls at all is IAC-149's condition and is never reported
// here. A file that does not parse as Kubernetes (a Helm template, for one) is
// not evaluated: the rule cannot know what a `{{- if .Values.ingress.tls }}`
// renders, so it says nothing rather than guess.

func dropIngressTLSNotEstablished(in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	has := false
	for i := range in {
		if in[i].RuleID == "IAC-296" {
			has = true
			break
		}
	}
	if !has {
		return in
	}
	var resources []structural.Resource
	if !strings.Contains(string(content), "{{") {
		if docs, err := structural.Parse(content); err == nil {
			resources = structural.Resources(docs)
		}
	}
	lines := make([]int, len(resources))
	for i := range resources {
		lines[i] = resources[i].Line
	}
	kept := in[:0]
	for _, f := range in {
		if f.RuleID != "IAC-296" {
			kept = append(kept, f)
			continue
		}
		reason := "the document could not be evaluated (a template, or not a Kubernetes manifest)"
		if i := sort.SearchInts(lines, f.Location.StartLine+1) - 1; i >= 0 && strings.EqualFold(resources[i].Type, "Ingress") {
			ok, why := ingressTLSGap(resources[i].Props)
			if ok {
				kept = append(kept, f)
				continue
			}
			reason = why
		}
		drop(f, reason)
	}
	return kept
}

// ingressTLSGap reports whether the Ingress has a TLS gap, or why not.
func ingressTLSGap(ing *yaml.Node) (gap bool, reason string) {
	spec := mapChild(ing, "spec")
	tls := mapChild(spec, "tls")
	if tls == nil || tls.Kind != yaml.SequenceNode || len(tls.Content) == 0 {
		return false, "no tls block: that condition belongs to IAC-149"
	}
	var covered []string
	coversAll := false
	certAnnotated := hasCertAnnotation(mapChild(mapChild(ing, "metadata"), "annotations"))
	for _, e := range tls.Content {
		hosts := mapChild(e, "hosts")
		if hosts == nil || len(hosts.Content) == 0 {
			coversAll = true // the default entry
		} else {
			for _, h := range hosts.Content {
				covered = append(covered, strings.ToLower(h.Value))
			}
		}
		if mapChild(e, "secretName") == nil && !certAnnotated {
			return true, ""
		}
	}
	if coversAll {
		return false, "tls covers every host and names a certificate source"
	}
	rules := mapChild(spec, "rules")
	if rules != nil {
		for _, r := range rules.Content {
			h := mapChild(r, "host")
			if h == nil || h.Value == "" || strings.Contains(h.Value, "{{") || strings.Contains(h.Value, "$") {
				continue
			}
			if !hostCovered(strings.ToLower(h.Value), covered) {
				return true, ""
			}
		}
	}
	return false, "every host is covered by a tls entry with a certificate source"
}

func mapChild(n *yaml.Node, key string) *yaml.Node {
	if n == nil || n.Kind != yaml.MappingNode {
		return nil
	}
	for i := 0; i+1 < len(n.Content); i += 2 {
		if n.Content[i].Value == key {
			v := n.Content[i+1]
			if v.Kind == yaml.AliasNode && v.Alias != nil {
				v = v.Alias
			}
			return v
		}
	}
	return nil
}

// hostCovered: an exact match, or a `*.example.com` entry covering exactly one
// extra label.
func hostCovered(host string, covered []string) bool {
	for _, c := range covered {
		if c == host {
			return true
		}
		if rest, ok := strings.CutPrefix(c, "*."); ok {
			if label, tail, found := strings.Cut(host, "."); found && label != "" && tail == rest {
				return true
			}
		}
	}
	return false
}

// hasCertAnnotation reports an annotation that provisions a certificate.
func hasCertAnnotation(a *yaml.Node) bool {
	if a == nil || a.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(a.Content); i += 2 {
		k := strings.ToLower(a.Content[i].Value)
		if strings.HasPrefix(k, "cert-manager.io/") || strings.HasPrefix(k, "cert-manager.k8s.io/") ||
			k == "kubernetes.io/tls-acme" || strings.HasSuffix(k, "/certificate-arn") ||
			strings.HasSuffix(k, "/ssl-cert") || strings.HasSuffix(k, "/certificate-name") {
			return true
		}
	}
	return false
}
