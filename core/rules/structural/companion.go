package structural

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

// Companion resolution answers a question the single-resource model cannot:
// whether a resource is protected by a DIFFERENT object declared elsewhere in
// the document set.
//
// Eight absence rules ask it. A VPC is unmonitored unless a flow log targets
// it; a Deployment is unprotected unless a PodDisruptionBudget selects it; a
// Namespace is unbounded unless a ResourceQuota names it; a SQL server is
// unaudited unless an auditingSettings child hangs off it. None of these
// properties is on the resource the rule is about, so no lookup within it can
// find them.
//
// What the text path does instead is search the whole file for the companion's
// NAME. That is wrong in both directions, and measurably so:
//
//   - It cannot see linkage. A PodDisruptionBudget selecting `app: api`
//     silences the rule for every workload in the file, including the three
//     that it does not select. The word appearing is treated as the protection
//     existing.
//   - It cannot see quantity. `absenceSpan: "file"` reports one finding at the
//     first anchor, so a manifest with four unprotected Deployments reports one.
//   - It matches text that is not a resource. `FlowLogsEnabled: false` in a tag
//     contains "FlowLog", so a VPC with logging explicitly turned OFF reads as
//     a VPC with logging configured.
//
// Resolving the companion structurally answers all three, and yields a claim a
// regex cannot make: the document set was parsed, its resources enumerated, and
// none of them is a flow log bound to this VPC.
//
// # The boundary this deliberately does not cross
//
// A document set is what one file contains. A PodDisruptionBudget living in a
// second file is not visible here, and "no companion in this file" is not "no
// companion anywhere". That limit is inherited, not introduced — the text rule
// it replaces is scoped to one file too — but it is the reason a companion
// verdict claims what was PARSED rather than what is DEPLOYED, and the reason
// Statement says "the document set" rather than "the cluster".

// Link is how a companion binds to the subject it protects.
//
// Each kind is a different question, and asking the wrong one silently answers
// "not bound" for every resource — which for an absence rule means inventing a
// finding on every one of them. The kind is therefore named per rule and never
// inferred from the types involved.
type Link string

const (
	// LinkRef — the companion references the subject's logical name through a
	// template intrinsic. CloudFormation's binding mechanism: a flow log names
	// its VPC in `Properties.ResourceId`, a rotation schedule names its secret
	// in `Properties.SecretId`.
	LinkRef Link = "ref"
	// LinkSelector — the companion's label selector matches the subject's pod
	// template labels. How a PodDisruptionBudget binds to a workload.
	LinkSelector Link = "selector"
	// LinkNamespace — the companion is scoped to the namespace the subject
	// declares. How a ResourceQuota or LimitRange binds to a Namespace.
	LinkNamespace Link = "namespace"
	// LinkChild — the companion is an ARM child resource of the subject,
	// declared either nested inside it or at the top level under a name the
	// parent's prefixes.
	LinkChild Link = "child"
)

// Companion describes the resource whose existence AND linkage satisfies a
// requirement the subject cannot express on itself.
type Companion struct {
	// Types are the companion's type, in the document's own spelling.
	Types []string
	// Link is how it binds to the subject.
	Link Link
	// Path, for LinkRef only, is where inside the companion the reference to
	// the subject is written.
	Path string
}

// linkage is the outcome of asking whether one companion binds to one subject.
//
// The third value is the point. "I cannot tell" is not "not bound": a selector
// written with matchExpressions, an ARM name that is an expression, or a
// reference to a template parameter are all cases where the answer needs
// information the file does not carry. Reading any of them as "not bound"
// would report a resource that is very likely protected, so an undecidable
// pair takes the whole file back to the text path instead.
type linkage int

const (
	unlinked linkage = iota
	linked
	undecidable
)

// EvaluateCompanion decides a cross-resource absence rule structurally.
//
// A subject is Absent when the document set contains no companion of the given
// type bound to it, and Present when one is found. The two absent cases are
// distinguished on the Hit — no companion at all, against a companion that
// binds elsewhere — because they are different findings to read and the second
// is the one the text path could never produce.
func EvaluateCompanion(content []byte, subjectTypes []string, c Companion) Verdict {
	return EvaluateCompanionWithSubject(content, subjectTypes, c, nil)
}

// EvaluateCompanionWithSubject is EvaluateCompanion with a precondition on the
// subject. See EvaluateWithSubject.
func EvaluateCompanionWithSubject(content []byte, subjectTypes []string, c Companion, subjectMinInt map[string]int) Verdict {
	if len(subjectTypes) == 0 || len(c.Types) == 0 || c.Link == "" {
		return Verdict{Reason: "rule carries no companion descriptor"}
	}
	if c.Link == LinkRef && c.Path == "" {
		return Verdict{Reason: "a ref companion needs the path holding the reference"}
	}

	docs, err := Parse(content)
	if err != nil {
		return Verdict{Reason: fmt.Sprintf("not parseable as YAML or JSON: %v", err)}
	}
	all := Resources(docs)
	if len(all) == 0 {
		return Verdict{Reason: "no CloudFormation, Kubernetes or ARM resources in the document"}
	}

	subjects := OfTypes(all, subjectTypes)
	companions := OfTypes(all, c.Types)
	companionType := c.Types[0]

	v := Verdict{Decided: true}
	for _, s := range subjects {
		if !subjectQualifies(s, subjectMinInt) {
			continue
		}
		hit := Hit{
			Type: s.Type, Name: s.Name, Line: s.Line, Family: s.Family,
			Companion: companionType,
		}

		bound := false
		for _, comp := range companions {
			switch c.resolve(s, comp, all) {
			case linked:
				bound = true
				hit.CompanionName = comp.Name
			case undecidable:
				// One pair nobody can decide makes the whole file undecided.
				// Reporting the other subjects while silently dropping this one
				// would be a verdict that looks complete and is not.
				return Verdict{Reason: fmt.Sprintf(
					"cannot resolve whether the %s at line %d binds to %s at line %d",
					comp.Type, comp.Line, s.Type, s.Line)}
			}
			if bound {
				break
			}
		}

		if bound {
			v.Present = append(v.Present, hit)
			continue
		}
		// A companion of the right type exists somewhere in the document set,
		// but none of them binds here. That is the finding the text path is
		// structurally incapable of reporting, so it is worth distinguishing.
		hit.Unlinked = len(companions) > 0
		v.Absent = append(v.Absent, hit)
	}
	return v
}

// resolve asks the linkage question this companion is defined by.
func (c Companion) resolve(subject, comp Resource, all []Resource) linkage {
	// A resource cannot be its own companion. Types can legitimately overlap
	// (a rule may name the subject's own type among the companions), and
	// without this a resource would satisfy its own requirement.
	if subject.Props == comp.Props {
		return unlinked
	}
	switch c.Link {
	case LinkRef:
		return linkByRef(subject, comp, c.Path, all)
	case LinkSelector:
		return linkBySelector(subject, comp)
	case LinkNamespace:
		return linkByNamespace(subject, comp)
	case LinkChild:
		return linkByChild(subject, comp)
	default:
		return undecidable
	}
}

// linkByRef resolves a CloudFormation intrinsic reference.
//
// Referencing a resource declared in the same template REQUIRES an intrinsic —
// `!Ref`, `Fn::GetAtt`, `Fn::Sub` — so a literal string in the reference slot
// names something outside the template and binds to nothing here. That is a
// decidable "no", not an unknown, and it is exactly the case the text path gets
// wrong: a flow log for a pre-existing VPC silences the rule for the VPC this
// template creates.
//
// A reference to a name that is not a resource in the template — a parameter,
// a pseudo-parameter — is undecidable rather than unlinked, because the
// parameter may well carry the subject at deployment time and the file cannot
// say.
func linkByRef(subject, comp Resource, path string, all []Resource) linkage {
	if subject.Family != FamilyCloudFormation || comp.Family != FamilyCloudFormation {
		return undecidable
	}
	if subject.Name == "" {
		return undecidable
	}
	target := nodeAt(comp.Props, path)
	if target == nil {
		// The companion does not set the property that would bind it. It binds
		// to nothing, which is a fact about this companion, not an unknown.
		return unlinked
	}

	names := templateRefs(target, 0)
	if len(names) == 0 {
		return unlinked
	}
	declared := make(map[string]bool, len(all))
	for _, r := range all {
		if r.Family == FamilyCloudFormation && r.Name != "" {
			declared[r.Name] = true
		}
	}
	external := false
	for _, n := range names {
		if n == subject.Name {
			return linked
		}
		if !declared[n] {
			external = true
		}
	}
	if external {
		return undecidable
	}
	return unlinked
}

// templateRefs collects the logical names a node references.
//
// It reads the intrinsic forms syntactically and never evaluates them, in
// keeping with the rest of the package: `!Ref Vpc` references "Vpc" whatever
// "Vpc" turns out to be at deployment time. Both notations are handled because
// one template may use either — the YAML short form (`!Ref`, `!GetAtt`,
// `!Sub`) and the JSON long form (`Ref`, `Fn::GetAtt`, `Fn::Sub`) are the same
// document to CloudFormation and must be the same document here.
func templateRefs(n *yaml.Node, depth int) []string {
	n = resolve(n)
	if n == nil || depth > maxAliasDepth {
		return nil
	}
	var out []string
	switch n.Kind {
	case yaml.ScalarNode:
		switch n.Tag {
		case "!Ref":
			out = append(out, n.Value)
		case "!GetAtt":
			out = append(out, logicalNameOf(n.Value))
		case "!Sub":
			out = append(out, subRefs(n.Value)...)
		}
	case yaml.SequenceNode:
		for _, el := range n.Content {
			out = append(out, templateRefs(el, depth+1)...)
		}
	case yaml.MappingNode:
		for i := 0; i+1 < len(n.Content); i += 2 {
			key, val := n.Content[i].Value, resolve(n.Content[i+1])
			switch key {
			case "Ref":
				if val != nil && val.Kind == yaml.ScalarNode {
					out = append(out, val.Value)
				}
			case "Fn::GetAtt":
				// Either ["Logical", "Attr"] or the "Logical.Attr" string.
				if val == nil {
					continue
				}
				if val.Kind == yaml.SequenceNode && len(val.Content) > 0 {
					out = append(out, val.Content[0].Value)
				} else if val.Kind == yaml.ScalarNode {
					out = append(out, logicalNameOf(val.Value))
				}
			case "Fn::Sub":
				// Either "text ${Logical}" or ["text ${Logical}", {vars}].
				if val == nil {
					continue
				}
				if val.Kind == yaml.SequenceNode && len(val.Content) > 0 {
					out = append(out, subRefs(val.Content[0].Value)...)
				} else if val.Kind == yaml.ScalarNode {
					out = append(out, subRefs(val.Value)...)
				}
			default:
				out = append(out, templateRefs(val, depth+1)...)
			}
		}
	}
	return out
}

// logicalNameOf takes the resource half of a "Logical.Attribute" GetAtt.
func logicalNameOf(v string) string {
	name, _, _ := strings.Cut(v, ".")
	return name
}

// subRefs extracts the ${Name} placeholders of an Fn::Sub string.
//
// `${!Literal}` is CloudFormation's escape for a literal `${…}` and references
// nothing, so it is skipped rather than read as a resource called "!Literal".
func subRefs(s string) []string {
	var out []string
	for {
		start := strings.Index(s, "${")
		if start < 0 {
			return out
		}
		s = s[start+2:]
		end := strings.Index(s, "}")
		if end < 0 {
			return out
		}
		ref := s[:end]
		s = s[end+1:]
		if strings.HasPrefix(ref, "!") {
			continue
		}
		if name := logicalNameOf(ref); name != "" {
			out = append(out, name)
		}
	}
}

// linkBySelector resolves a Kubernetes label selector against a workload's pod
// template labels.
//
// The quantifier is the one Kubernetes uses: a selector binds when EVERY label
// it requires is present on the pod with the same value. A selector requiring
// two labels of which the pod carries one does not select that pod, and reading
// it as a match would silence the rule for a workload nothing protects.
func linkBySelector(subject, comp Resource) linkage {
	if subject.Family != FamilyKubernetes || comp.Family != FamilyKubernetes {
		return undecidable
	}
	if !namespacesCompatible(subject, comp) {
		return unlinked
	}

	sel := mapValue(mapValue(comp.Props, "spec"), "selector")
	if sel == nil {
		// A budget with no selector applies to everything in its namespace.
		return linked
	}
	if mapValue(sel, "matchExpressions") != nil {
		// Set-based requirements are a small language of their own (In, NotIn,
		// Exists, DoesNotExist). Nothing here evaluates it, and guessing would
		// decide a resource's fate on a selector this package cannot read.
		return undecidable
	}
	match := mapValue(sel, "matchLabels")
	if match == nil || len(match.Content) == 0 {
		// An empty selector selects every pod in the namespace. That is
		// Kubernetes' rule, and it is the opposite of HasAll's empty case:
		// there, nothing satisfied the requirement; here, the requirement asks
		// for nothing.
		return linked
	}

	labels := podLabels(subject.Props)
	if labels == nil {
		// A workload whose pod template carries no labels cannot be matched by
		// any selector, but a manifest that omits them is more likely relying
		// on generation than declaring an unselectable pod.
		return undecidable
	}
	for i := 0; i+1 < len(match.Content); i += 2 {
		key, want := match.Content[i].Value, resolve(match.Content[i+1])
		if want == nil || want.Kind != yaml.ScalarNode {
			return undecidable
		}
		got := mapValue(labels, key)
		if got == nil || got.Kind != yaml.ScalarNode {
			return unlinked
		}
		if got.Value != want.Value {
			return unlinked
		}
	}
	return linked
}

// podLabels returns a workload's pod template labels.
//
// `spec.template.metadata.labels` for a Deployment, StatefulSet, DaemonSet or
// Job; `metadata.labels` for a bare Pod, which has no template. A selector
// matches the POD's labels, never the workload's own, and the two routinely
// differ — which is why this does not simply read `metadata.labels`.
func podLabels(props *yaml.Node) *yaml.Node {
	spec := mapValue(props, "spec")
	if tmpl := mapValue(spec, "template"); tmpl != nil {
		if l := mapValue(mapValue(tmpl, "metadata"), "labels"); l != nil {
			return l
		}
		return nil
	}
	if kind := scalarAt(props, "kind"); kind == "Pod" {
		return mapValue(mapValue(props, "metadata"), "labels")
	}
	return nil
}

// namespacesCompatible reports whether two objects could be in the same
// namespace.
//
// An omitted namespace is not "the default namespace": it is a namespace
// supplied at apply time, by `kubectl -n` or by the kustomization or chart that
// renders the manifest. Treating omission as a mismatch would report every
// workload in every namespace-agnostic manifest — which is most of them — so
// only two namespaces that are both stated and different are incompatible.
func namespacesCompatible(a, b Resource) bool {
	na := scalarAt(mapValue(a.Props, "metadata"), "namespace")
	nb := scalarAt(mapValue(b.Props, "metadata"), "namespace")
	if na == "" || nb == "" {
		return true
	}
	return na == nb
}

// linkByNamespace resolves a namespaced object against the Namespace it is
// scoped to.
func linkByNamespace(subject, comp Resource) linkage {
	if subject.Family != FamilyKubernetes || comp.Family != FamilyKubernetes {
		return undecidable
	}
	name := scalarAt(mapValue(subject.Props, "metadata"), "name")
	if name == "" {
		return undecidable
	}
	ns := scalarAt(mapValue(comp.Props, "metadata"), "namespace")
	if ns == "" {
		// Same reasoning as namespacesCompatible: a quota with no namespace is
		// scoped when it is applied, and this file cannot say to where.
		return undecidable
	}
	if ns == name {
		return linked
	}
	return unlinked
}

// linkByChild resolves an ARM child resource against its parent.
//
// ARM allows the same child two spellings, and both are handled because both
// appear in real templates:
//
//   - nested inside the parent's `resources` array, where the nesting IS the
//     binding and no name has to be read;
//   - at the top level, where the child's name carries the parent's as its
//     first segment ("sqlserver1/DefaultAuditing").
//
// The second form is frequently written as an expression — `[concat(
// parameters('serverName'), '/audit')]` — and this package does not evaluate
// expressions, so those pairs are undecidable and take the file back to the
// text path rather than guessing.
func linkByChild(subject, comp Resource) linkage {
	if subject.Family != FamilyARM || comp.Family != FamilyARM {
		return undecidable
	}
	if comp.Parent != nil {
		// Nested. Pointer identity, so an expression name decides nothing.
		if comp.Parent == subject.Props {
			return linked
		}
		return unlinked
	}
	if subject.Name == "" || comp.Name == "" {
		return undecidable
	}
	if isARMExpression(subject.Name) || isARMExpression(comp.Name) {
		return undecidable
	}
	parent, _, ok := strings.Cut(comp.Name, "/")
	if !ok {
		// A top-level child whose name carries no parent segment is malformed
		// for this schema; nothing can be concluded from it.
		return undecidable
	}
	if parent == subject.Name {
		return linked
	}
	return unlinked
}

// isARMExpression reports whether a value is an ARM template expression rather
// than a literal.
func isARMExpression(v string) bool {
	return strings.HasPrefix(v, "[") && strings.HasSuffix(v, "]")
}
