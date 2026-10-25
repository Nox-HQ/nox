package threatmodel

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/findings"
)

var cweRe = regexp.MustCompile(`CWE-\d+`)

// categoriesFor returns the STRIDE categories a finding is evidence for, from
// the rule when the rule is named in strideByRule and from the weakness (CWE)
// the finding declares otherwise. It returns nil for a finding whose weakness
// this mapping does not cover: such a finding is listed apart, never forced
// into a category.
func categoriesFor(f findings.Finding) []Category {
	if cats, ok := strideByRule[f.RuleID]; ok {
		return cats
	}
	seen := map[Category]bool{}
	var out []Category
	for _, cwe := range cweRe.FindAllString(f.Metadata["cwe"], -1) {
		for _, row := range strideByCWE {
			if !containsString(row.cwes, cwe) {
				continue
			}
			for _, c := range row.cats {
				if !seen[c] {
					seen[c] = true
					out = append(out, c)
				}
			}
		}
	}
	return out
}

func containsString(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// attach returns the elements a finding is about. A finding on a file belongs
// to the elements located in that file; to a route only when it sits at or
// below that route's registration and above the next one. A supply-chain
// finding belongs to the dependencies. It returns nothing when no element
// accounts for the finding.
func (b *builder) attach(f findings.Finding) []*elem {
	if isSupplyChainRule(f.RuleID) {
		if e, ok := b.elems["dependencies"]; ok {
			return []*elem{e}
		}
		return nil
	}
	file := f.Location.FilePath
	if e := b.resourceFor(f); e != nil {
		// The rule names the kind of resource and the inventory says which
		// one the finding sits in.
		return []*elem{e}
	}
	var out []*elem
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		if e.Kind == KindRoute || !e.files[file] || !aboutKind(f.RuleID, e.Kind) {
			continue
		}
		// A file that holds several infrastructure resources (one Terraform
		// file with a bucket, a database and a security group) cannot say
		// which of them a finding is about. A finding is attached to such an
		// element only when its rule names that kind of resource; any other
		// finding in the file belongs to none of them.
		if e.resource != nil && b.infraPerFile[file] > 1 {
			continue
		}
		if e.infra != nil && b.infraPerFile[file] > 1 {
			row, named := iacRules[f.RuleID]
			if !named || row.kind != e.infra.kind || row.sub != e.infra.sub {
				continue
			}
		}
		out = append(out, e)
	}
	if r := b.routeFor(file, f.Location.StartLine); r != nil && aboutKind(f.RuleID, KindRoute) {
		out = append(out, r)
	}
	return out
}

// findingAcc collects the findings behind one cell, active and waived apart.
type findingAcc struct {
	active, waived []findings.Finding
}

// aboutKind reports whether a rule can be about an element of the given kind.
// Most rules say nothing about what in a file they concern, so file is all the
// model has; the agent rules are the exception, because they are about the
// tools an agent registers and a model reference in the same file is not that.
func aboutKind(ruleID, kind string) bool {
	if strings.HasPrefix(ruleID, "AI-AGENT-") || strings.HasPrefix(ruleID, "AGENTFLOW-") {
		return kind == KindAgent
	}
	return true
}

// rows computes the STRIDE table and the count of findings no element accounts
// for.
func (b *builder) rows() (rows []Row, unattributed int) {
	// element id -> category -> findings; element id -> unmapped findings.
	cells := map[string]map[Category]*findingAcc{}
	other := map[string]*findingAcc{}
	for _, list := range [][]findings.Finding{b.active, b.waived} {
		isWaived := len(list) > 0 && !list[0].Status.IsActive()
		for _, f := range list {
			els := b.attach(f)
			if len(els) == 0 {
				if !isWaived {
					unattributed++
				}
				continue
			}
			cats := categoriesFor(f)
			for _, e := range els {
				if len(cats) == 0 {
					acc := other[e.ID]
					if acc == nil {
						acc = &findingAcc{}
						other[e.ID] = acc
					}
					if isWaived {
						acc.waived = append(acc.waived, f)
					} else {
						acc.active = append(acc.active, f)
					}
					continue
				}
				for _, c := range cats {
					if cells[e.ID] == nil {
						cells[e.ID] = map[Category]*findingAcc{}
					}
					acc := cells[e.ID][c]
					if acc == nil {
						acc = &findingAcc{}
						cells[e.ID][c] = acc
					}
					if isWaived {
						acc.waived = append(acc.waived, f)
					} else {
						acc.active = append(acc.active, f)
					}
				}
			}
		}
	}

	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		if !hasRow(e.Kind) {
			continue
		}
		row := Row{Element: id}
		for _, cat := range Categories {
			row.Cells = append(row.Cells, buildCell(e, cat, cells[id][cat]))
		}
		if acc := other[id]; acc != nil {
			row.Other = append(groupFindings(acc.active, false), groupFindings(acc.waived, true)...)
			sortEvidence(row.Other)
		}
		rows = append(rows, row)
	}
	return rows, unattributed
}

// hasRow reports whether an element kind is assessed. Actors, the application
// as a whole and the effect targets of flows are not things a threat is
// assessed against; they are the ends of flows.
func hasRow(kind string) bool {
	switch kind {
	case KindActor, KindApplication, KindCapability, KindMCPClient:
		return false
	}
	return true
}

func buildCell(e *elem, cat Category, acc *findingAcc) Cell {
	cell := Cell{Category: cat, Evidence: []Evidence{}}
	if acc != nil {
		cell.Evidence = append(cell.Evidence, groupFindings(acc.active, false)...)
		cell.Evidence = append(cell.Evidence, groupFindings(acc.waived, true)...)
		cell.Findings, cell.Waived = len(acc.active), len(acc.waived)
	}
	status := NotEvidenced
	if cell.Findings > 0 {
		status = OpenIssues
	}
	for _, o := range e.obs {
		if o.cat != cat {
			continue
		}
		cell.Evidence = append(cell.Evidence, o.ev)
		if o.status == LeadsToVerify {
			cell.Leads++
		}
		if statusRank(o.status) < statusRank(status) {
			status = o.status
		}
	}
	if status == NotEvidenced && cell.Waived > 0 {
		status = LimitedEvidence
	}
	sortEvidence(cell.Evidence)
	cell.Status = status
	if status == NotEvidenced {
		cell.Note = "nox has no evidence either way"
	}
	return cell
}

// compactRef strips the line from a file:line reference, so two runs that
// differ only in a moved line compare equal.
func compactRef(ref string) string {
	if i := strings.LastIndex(ref, ":"); i > 0 {
		if _, err := strconv.Atoi(ref[i+1:]); err == nil {
			return ref[:i]
		}
	}
	return ref
}

// stableKey identifies a piece of evidence independent of line numbers, so a
// comparison reports a change in what is evidenced and not in where it sits.
func (e Evidence) stableKey() string {
	if e.RuleID != "" {
		return e.RuleID + "@" + compactRef(e.Ref) + " x" + strconv.Itoa(e.Count) + waivedSuffix(e.Waived)
	}
	return e.Artifact + ": " + stripLines(e.Statement)
}

func waivedSuffix(w bool) string {
	if w {
		return " (waived)"
	}
	return ""
}

var lineSuffix = regexp.MustCompile(`:\d+`)

func stripLines(s string) string { return lineSuffix.ReplaceAllString(s, "") }

func sortRows(rows []Row) {
	sort.SliceStable(rows, func(i, j int) bool { return rows[i].Element < rows[j].Element })
}
