package structural

import (
	"strings"

	"gopkg.in/yaml.v3"
)

// isCloudFormation reports whether a document root is a CloudFormation
// template.
//
// The test is the shape the schema guarantees — a `Resources` mapping whose
// values carry a `Type` scalar — rather than the presence of
// `AWSTemplateFormatVersion`, which is optional and absent from most real
// templates. Requiring at least one typed resource is what keeps a
// docker-compose file or a Helm values file, both of which may have a
// `Resources` key meaning something else entirely, from being read as a
// template.
func isCloudFormation(r *yaml.Node) bool {
	res := mapValue(r, "Resources")
	if res == nil || res.Kind != yaml.MappingNode {
		return false
	}
	for i := 0; i+1 < len(res.Content); i += 2 {
		if t := scalarAt(res.Content[i+1], "Type"); t != "" {
			return true
		}
	}
	return false
}

// cloudFormationResources enumerates the entries of the template's `Resources`
// mapping.
//
// Props is the resource body, so paths are written `Properties.BucketEncryption`.
// A resource with no `Properties` key resolves every such path to absent,
// correctly: a bucket declared with no properties at all has no encryption
// configured.
func cloudFormationResources(r *yaml.Node) []Resource {
	res := mapValue(r, "Resources")
	if res == nil || res.Kind != yaml.MappingNode {
		return nil
	}
	var out []Resource
	for i := 0; i+1 < len(res.Content); i += 2 {
		nameNode, body := res.Content[i], resolve(res.Content[i+1])
		typ := scalarAt(body, "Type")
		if typ == "" {
			continue
		}
		out = append(out, Resource{
			Family: FamilyCloudFormation,
			Type:   typ,
			Name:   nameNode.Value,
			Props:  body,
			Line:   nameNode.Line,
		})
	}
	return out
}

// isARM reports whether a document root is an Azure Resource Manager template.
//
// Checked before Kubernetes because an ARM template has neither `kind` nor
// `apiVersion` at the root, and after CloudFormation because the two are
// distinguished by the case of their resources key — `Resources` against
// `resources` — which is a thin distinction to rest on, so the CloudFormation
// test runs first and takes anything that satisfies it.
func isARM(r *yaml.Node) bool {
	if schema := scalarAt(r, "$schema"); strings.Contains(schema, "deploymentTemplate") {
		return true
	}
	res := mapValue(r, "resources")
	if res == nil {
		return false
	}
	// ARM's `resources` is a sequence (or, since the 2021 language revision, a
	// mapping keyed by symbolic name) of objects carrying `type` and
	// `apiVersion`. Requiring both is what separates it from any other document
	// that happens to have a `resources` key.
	for _, el := range armElements(res) {
		if scalarAt(el, "type") != "" && scalarAt(el, "apiVersion") != "" {
			return true
		}
	}
	return false
}

// armElements returns the resource objects of an ARM `resources` node, which
// the language allows to be either a sequence or a symbolic-name mapping.
func armElements(res *yaml.Node) []*yaml.Node {
	res = resolve(res)
	if res == nil {
		return nil
	}
	var out []*yaml.Node
	switch res.Kind {
	case yaml.SequenceNode:
		for _, el := range res.Content {
			if el = resolve(el); el != nil && el.Kind == yaml.MappingNode {
				out = append(out, el)
			}
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(res.Content); i += 2 {
			if el := resolve(res.Content[i+1]); el != nil && el.Kind == yaml.MappingNode {
				out = append(out, el)
			}
		}
	}
	return out
}

// armResources enumerates an ARM template's resources, including nested ones.
//
// Nesting is followed because ARM lets a resource declare child resources
// inline — a storage account's blob service, a SQL server's databases — and a
// rule about the child would otherwise never see it. The depth bound is the
// same reasoning as maxAliasDepth: the document is attacker-controllable.
func armResources(r *yaml.Node) []Resource {
	var out []Resource
	var walk func(n *yaml.Node, depth int)
	walk = func(n *yaml.Node, depth int) {
		if depth > maxAliasDepth {
			return
		}
		for _, el := range armElements(mapValue(n, "resources")) {
			typ := scalarAt(el, "type")
			if typ == "" {
				continue
			}
			out = append(out, Resource{
				Family: FamilyARM,
				Type:   typ,
				Name:   scalarAt(el, "name"),
				Props:  el,
				Line:   el.Line,
			})
			walk(el, depth+1)
		}
	}
	walk(r, 0)
	return out
}
