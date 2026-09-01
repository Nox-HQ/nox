package structural

import (
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// Family is the document schema a resource was read from.
//
// It is recorded rather than inferred at use, because the three schemas name
// the same concept differently and a lookup written against the wrong one
// silently finds nothing — which for an absence rule reads as "the property is
// missing", the false positive this package exists to remove.
type Family string

const (
	// FamilyCloudFormation — an AWS CloudFormation template, JSON or YAML.
	FamilyCloudFormation Family = "cloudformation"
	// FamilyKubernetes — a Kubernetes manifest, possibly multi-document.
	FamilyKubernetes Family = "kubernetes"
	// FamilyARM — an Azure Resource Manager deployment template.
	FamilyARM Family = "arm"
)

// Resource is one addressable resource in a parsed document.
type Resource struct {
	// Family is the schema this was read from.
	Family Family
	// Type is the resource type as the document spells it: "AWS::S3::Bucket",
	// "Deployment", "Microsoft.Storage/storageAccounts".
	Type string
	// Name is the logical name the document gives it, when it gives one.
	Name string
	// Props is the resource OBJECT, and paths are addressed from it.
	//
	// It is deliberately the whole object rather than a per-family "properties"
	// sub-mapping, because the three schemas disagree about what lives inside
	// one: ARM puts `identity`, `sku` and `kind` BESIDE `properties`, not in
	// it, so a model that silently descended into `properties` could not
	// address half the fields the rules care about. Making the descent explicit
	// in the path — `properties.encryption`, `Properties.BucketEncryption`,
	// `spec.template.spec` — costs one segment and removes a whole class of
	// lookup that resolves to nothing for a reason the rule author cannot see.
	Props *yaml.Node
	// Line is the 1-based line the resource is declared on.
	Line int
	// Parent is the Props node of the resource this one is declared INSIDE,
	// or nil for a top-level resource. ARM is the only schema that nests, and
	// nesting is itself a binding: a SQL server's `auditingSettings` declared
	// inside the server's `resources` array belongs to that server and to no
	// other, whatever either of them is named.
	//
	// Identity is the parent's node pointer rather than its name, because ARM
	// names are usually expressions (`[parameters('serverName')]`) that this
	// package will not evaluate. Comparing pointers answers "is this the same
	// declaration?" exactly, and yaml.v3 allocates one node per declaration, so
	// sorting the resource slice cannot invalidate it.
	Parent *yaml.Node
	// ParentType is the parent's Type, kept so QualifiedType can spell a
	// nested child the way a top-level declaration of it would be spelled.
	ParentType string
}

// QualifiedType returns the type a rule author writes to name this resource.
//
// ARM allows one child resource to be declared two ways — nested inside its
// parent as `type: auditingSettings`, or at the top level as
// `type: Microsoft.Sql/servers/auditingSettings` — and they mean the same
// thing. A rule naming the child must match both, so a nested type is
// qualified with its parent's. A type that already carries a "/" is left
// alone: ARM permits the fully-qualified spelling in the nested position too,
// and qualifying it twice would match nothing.
func (r Resource) QualifiedType() string {
	if r.ParentType == "" || strings.Contains(r.Type, "/") {
		return r.Type
	}
	return r.ParentType + "/" + r.Type
}

// Resources enumerates every resource in the parsed documents.
//
// A document whose schema is not recognised contributes nothing. That is the
// signal callers use to fall back to text matching: "parsed, but this is not a
// document I understand" must never be confused with "parsed, and it has no
// such resource", because the first is ignorance and the second is a finding.
//
// The result is ordered by document, then by declaration line, so a scan over
// the same bytes always reports in the same order.
func Resources(docs []*yaml.Node) []Resource {
	var out []Resource
	for _, doc := range docs {
		r := root(doc)
		if r == nil {
			continue
		}
		switch {
		case isCloudFormation(r):
			out = append(out, cloudFormationResources(r)...)
		case isARM(r):
			out = append(out, armResources(r)...)
		case isKubernetes(r):
			out = append(out, kubernetesResources(r)...)
		}
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out
}

// OfTypes returns the resources whose Type matches any of types.
//
// A set rather than one type because Kubernetes asks the same question of every
// kind that carries a pod template — Deployment, StatefulSet, DaemonSet, Job —
// and splitting that into one rule per kind would multiply the catalogue
// without changing what it detects.
//
// Comparison is case-insensitive because rule authors write the type by hand
// and the three schemas disagree about case ("AWS::S3::Bucket" against
// "Microsoft.Storage/storageAccounts"), while none of them has two types that
// differ only by case — so folding case cannot merge two distinct resources.
func OfTypes(resources []Resource, types []string) []Resource {
	var out []Resource
	for _, r := range resources {
		if matchesAnyType(r, types) {
			out = append(out, r)
		}
	}
	return out
}

// matchesAnyType reports whether r is named by any of types, under either its
// own spelling or its qualified one.
func matchesAnyType(r Resource, types []string) bool {
	qualified := r.QualifiedType()
	for _, t := range types {
		if strings.EqualFold(r.Type, t) || strings.EqualFold(qualified, t) {
			return true
		}
	}
	return false
}
