package structural

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// Has reports whether path resolves to a set value within props.
//
// Path syntax, deliberately small — it addresses document structure and nothing
// else, because anything more expressive would be a query language nobody can
// review inside a security rule:
//
//	Key             a mapping key
//	a.b.c           nested mapping keys
//	a[].b           descend through EVERY element of a sequence
//	a.*.b           descend through EVERY value of a mapping
//
// A wildcard succeeds when ANY branch resolves. That is the right quantifier
// for the hardening question these rules ask — "is encryption configured?" —
// but it is the wrong one for "is every container hardened?", and rules of the
// second kind must not use this. See HasAll.
func Has(props *yaml.Node, path string) bool {
	return resolvePath(props, splitPath(path), false)
}

// HasAll reports whether path resolves on EVERY branch a wildcard opens.
//
// Kubernetes needs this and CloudFormation does not: a pod is only hardened
// when every container in it is, so a `containers[].securityContext` lookup
// that succeeds on one of three containers has found a vulnerable pod, not a
// safe one. Has would call that present and drop the finding — the failure
// direction that hides a real issue, which is why the two quantifiers are
// separate functions rather than a boolean argument someone can get backwards.
//
// An empty branch set is FALSE, not vacuously true: a pod with no containers
// has nothing hardened, and reporting "all of nothing satisfies it" is how an
// empty collection becomes an all-clear.
func HasAll(props *yaml.Node, path string) bool {
	return resolvePath(props, splitPath(path), true)
}

// splitPath breaks a path into segments, keeping "[]" as its own step so the
// walker handles exactly one operation per step.
func splitPath(path string) []string { return expandMarkers(path) }

// expandMarkers produces the segment list, keeping "[]" as its own step.
func expandMarkers(path string) []string {
	var out []string
	for _, seg := range strings.Split(path, ".") {
		if seg == "" {
			continue
		}
		markers := 0
		for strings.HasSuffix(seg, "[]") {
			seg = strings.TrimSuffix(seg, "[]")
			markers++
		}
		if seg != "" {
			out = append(out, seg)
		}
		for i := 0; i < markers; i++ {
			out = append(out, "[]")
		}
	}
	return out
}

// resolvePath walks segs from n.
//
// all selects the quantifier at every wildcard: false succeeds when any branch
// resolves, true requires all of them.
func resolvePath(n *yaml.Node, segs []string, all bool) bool {
	n = resolve(n)
	if n == nil {
		return false
	}
	if len(segs) == 0 {
		return isSet(n)
	}

	seg, rest := segs[0], segs[1:]
	switch seg {
	case "[]":
		if n.Kind != yaml.SequenceNode {
			return false
		}
		return quantify(n.Content, rest, all)
	case "*":
		if n.Kind != yaml.MappingNode {
			return false
		}
		var values []*yaml.Node
		for i := 0; i+1 < len(n.Content); i += 2 {
			values = append(values, n.Content[i+1])
		}
		return quantify(values, rest, all)
	default:
		return resolvePath(mapValue(n, seg), rest, all)
	}
}

// quantify applies the any/all quantifier over a wildcard's branches.
func quantify(branches []*yaml.Node, rest []string, all bool) bool {
	if len(branches) == 0 {
		// Empty under either quantifier is false. Under "any" that is
		// arithmetic; under "all" it is a decision — see HasAll.
		return false
	}
	for _, b := range branches {
		got := resolvePath(b, rest, all)
		if all && !got {
			return false
		}
		if !all && got {
			return true
		}
	}
	return all
}

// isSet reports whether a resolved node counts as a value the author supplied.
//
// A YAML null (`key:` with nothing after it, or an explicit `~`) is NOT set:
// writing the key and leaving it empty configures nothing, and treating it as
// present would let an empty key silence a hardening rule. An empty mapping or
// sequence IS set, because `BucketEncryption: {}` is a value the deployment
// will act on, and deciding what it evaluates to is beyond what this file can
// answer.
//
// An intrinsic function (`!Ref`, `!GetAtt`, an ARM `[[ ... ]]` string) is set:
// the author configured the property, and resolving the reference needs the
// deployment context, which is not here. Calling it absent would report a
// resource that IS configured, through the one mechanism templates use most.
func isSet(n *yaml.Node) bool {
	if n == nil {
		return false
	}
	if n.Tag == "!!null" {
		return false
	}
	if n.Kind == yaml.ScalarNode && n.Value == "" && n.Style == 0 {
		// An unquoted empty scalar is the same "key with nothing after it"
		// case; a quoted "" is an explicit empty string and stays set.
		return false
	}
	return true
}
