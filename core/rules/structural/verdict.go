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

	// Companion, when set, is the resource type whose existence and linkage the
	// rule required — a PodDisruptionBudget for a workload, a flow log for a
	// VPC. It switches Statement to the cross-resource sentences, because what
	// was established is about the document set and not about this resource's
	// own properties.
	Companion string
	// CompanionName names the bound companion on a Present hit.
	CompanionName string
	// Unlinked distinguishes the two ways a companion can be missing: false
	// means the document set declares none of that type at all, true means it
	// declares one that binds to something else. The second is the finding no
	// text search can produce, and reading it as the first would understate
	// what parsing established.
	Unlinked bool
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
	return EvaluateWithSubject(content, resourceTypes, propertyPaths, requireAll, nil)
}

// EvaluateWithSubject is Evaluate with a precondition on the subject: a
// resource is only judged when every path in subjectMinInt holds an integer of
// at least its value. A resource that fails the precondition is neither Absent
// nor Present — the rule does not apply to it, which is different from it
// being configured.
func EvaluateWithSubject(content []byte, resourceTypes, propertyPaths []string, requireAll bool, subjectMinInt map[string]int) Verdict {
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
		if !subjectQualifies(r, subjectMinInt) {
			continue
		}
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
	if h.Companion != "" {
		return h.companionStatement(name, absent)
	}
	if absent {
		return fmt.Sprintf("the %s resource %q (%s) was parsed and sets no %s",
			h.Family, name, h.Type, h.Property)
	}
	return fmt.Sprintf("the %s resource %q (%s) sets %s, which the rule's pattern did not match",
		h.Family, name, h.Type, h.Property)
}

// companionStatement renders a cross-resource outcome.
//
// It says "the document set" rather than "the cluster" on purpose: what was
// enumerated is one file's resources, and a companion in a second file is
// outside what this evidence covers. Overstating that scope is the way a
// per-file parse turns into a claim about a deployment.
func (h Hit) companionStatement(name string, absent bool) string {
	if !absent {
		companion := h.CompanionName
		if companion == "" {
			companion = "an unnamed resource"
		}
		return fmt.Sprintf("the %s resource %q (%s) is bound to the %s %q, a linkage the rule's pattern could not check",
			h.Family, name, h.Type, h.Companion, companion)
	}
	if h.Unlinked {
		return fmt.Sprintf("the %s resource %q (%s) was parsed, and every %s in the document set binds to a different resource",
			h.Family, name, h.Type, h.Companion)
	}
	return fmt.Sprintf("the %s resource %q (%s) was parsed, and the document set declares no %s",
		h.Family, name, h.Type, h.Companion)
}

// subjectQualifies reports whether a resource is in scope for a rule carrying a
// subject precondition. No precondition means every resource qualifies.
func subjectQualifies(r Resource, minInt map[string]int) bool {
	for path, min := range minInt {
		if !IntAtLeast(r.Props, path, min) {
			return false
		}
	}
	return true
}
