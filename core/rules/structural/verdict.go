package structural

import "fmt"

// Hit is one resource a structural evaluation decided about.
type Hit struct {
	// Type and Name identify the resource in the document.
	Type string
	Name string
	// Line is where the finding or refutation should point.
	Line int
	// Property is the path that decided it — the one found present, or the
	// last one checked when all were absent.
	Property string
	// Family is the schema the resource was read from.
	Family Family
}

// Verdict is the outcome of evaluating an absence rule structurally.
type Verdict struct {
	// Decided reports whether the document parsed AND its schema was
	// recognised. When false the caller must fall back to text matching:
	// "I could not read this" is not "there is nothing here", and conflating
	// them turns every unparseable file into an all-clear.
	Decided bool

	// Absent are resources of the rule's type that genuinely lack the
	// property. These become findings, and they carry a claim a regex cannot:
	// the document was parsed and the attribute is not set.
	Absent []Hit

	// Present are resources that DO set the property. These become
	// refutations. They matter more than the count suggests, because each one
	// is a finding the text path would have reported: the pattern could not see
	// a value that is there.
	Present []Hit

	// Reason explains a Decided=false verdict, for the degradation channel.
	Reason string
}

// Evaluate decides an absence rule against content structurally.
//
// resourceTypes are the document's own spelling of the types this rule is
// about; a resource matching any of them is evaluated. propertyPaths are
// alternatives: a resource is hardened when ANY of them is set, which mirrors
// the alternation the regex rules already use ("BucketEncryption|SSEAlgorithm")
// and keeps a migrated rule's meaning identical to the one it replaces.
//
// requireAll switches the quantifier used INSIDE a path's wildcards, not
// between the paths. Kubernetes rules need it — every container must be
// hardened, not any — and getting it wrong hides findings rather than inventing
// them, so it is an explicit argument at every call site.
func Evaluate(content []byte, resourceTypes, propertyPaths []string, requireAll bool) Verdict {
	if len(resourceTypes) == 0 || len(propertyPaths) == 0 {
		return Verdict{Reason: "rule carries no structural descriptor"}
	}

	docs, err := Parse(content)
	if err != nil {
		return Verdict{Reason: fmt.Sprintf("not parseable as YAML or JSON: %v", err)}
	}

	all := Resources(docs)
	if len(all) == 0 {
		// The bytes parsed but no schema this package understands was found.
		// That is ignorance, not absence, and it must read as such.
		return Verdict{Reason: "no CloudFormation, Kubernetes or ARM resources in the document"}
	}

	v := Verdict{Decided: true}
	for _, r := range OfTypes(all, resourceTypes) {
		hit := Hit{Type: r.Type, Name: r.Name, Line: r.Line, Family: r.Family}

		found := ""
		for _, path := range propertyPaths {
			ok := Has(r.Props, path)
			if requireAll {
				ok = HasAll(r.Props, path)
			}
			if ok {
				found = path
				break
			}
		}
		if found != "" {
			hit.Property = found
			v.Present = append(v.Present, hit)
			continue
		}
		hit.Property = propertyPaths[0]
		v.Absent = append(v.Absent, hit)
	}
	return v
}

// Statement renders what was established about a resource, for the evidence
// ledger. It names the schema, the resource and the property, so a reader can
// check the claim against the file rather than take it.
func (h Hit) Statement(absent bool) string {
	name := h.Name
	if name == "" {
		name = "an unnamed resource"
	}
	if absent {
		return fmt.Sprintf("the %s resource %q (%s) was parsed and sets no %s",
			h.Family, name, h.Type, h.Property)
	}
	return fmt.Sprintf("the %s resource %q (%s) sets %s, which the rule's pattern did not match",
		h.Family, name, h.Type, h.Property)
}
