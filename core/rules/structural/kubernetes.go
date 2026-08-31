package structural

import "gopkg.in/yaml.v3"

// isKubernetes reports whether a document root is a Kubernetes object.
//
// Both `apiVersion` and `kind` are required, because `kind` alone appears in
// plenty of documents that are not manifests — a CRD sample, a Helm value, an
// arbitrary config with a field called kind — and reading one of those as a
// Deployment would let a rule decide about a resource that is not there.
func isKubernetes(r *yaml.Node) bool {
	return scalarAt(r, "apiVersion") != "" && scalarAt(r, "kind") != ""
}

// kubernetesResources enumerates the objects in a Kubernetes document.
//
// Props is the object root, not a properties sub-mapping, because Kubernetes
// has no such key: an object's configuration is spread across `spec`,
// `metadata` and the top level, so paths are written from the root
// (`spec.template.spec.containers[].securityContext`). That difference from
// CloudFormation and ARM is the reason Resource carries Props at all rather
// than letting callers navigate from the object.
//
// A `List` is unwrapped into its items, so a rule about a Deployment still sees
// one inside a List — the form `kubectl get -o yaml` emits, and the form a
// manifest bundle most often takes.
func kubernetesResources(r *yaml.Node) []Resource {
	kind := scalarAt(r, "kind")
	if kind == "List" {
		var out []Resource
		items := mapValue(r, "items")
		if items == nil || items.Kind != yaml.SequenceNode {
			return nil
		}
		for _, el := range items.Content {
			el = resolve(el)
			if el == nil || !isKubernetes(el) {
				continue
			}
			out = append(out, kubernetesResources(el)...)
		}
		return out
	}

	line := r.Line
	// Report the finding on the `kind` line rather than the document's first
	// line: it is the line a reader looks at to see which resource this is, and
	// it is stable when the key order changes.
	if k := mapValue(r, "kind"); k != nil {
		line = k.Line
	}
	return []Resource{{
		Family: FamilyKubernetes,
		Type:   kind,
		Name:   scalarAt(mapValue(r, "metadata"), "name"),
		Props:  r,
		Line:   line,
	}}
}
