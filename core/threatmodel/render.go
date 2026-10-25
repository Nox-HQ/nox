package threatmodel

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/infra"
)

// JSON renders the model as indented JSON with a trailing newline. The output
// depends only on m, so the same evidence gives the same bytes.
func (m Model) JSON() ([]byte, error) {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(m); err != nil {
		return nil, err
	}
	return buf.Bytes(), nil
}

// statusLabel is the plain-language heading for a status.
func statusLabel(s Status) string {
	switch s {
	case OpenIssues:
		return "Open issues"
	case LeadsToVerify:
		return "Leads to verify"
	case LimitedEvidence:
		return "Context only"
	}
	return "Not evidenced"
}

// kindOrder is the order element kinds are listed in.
var kindOrder = []string{
	KindRoute, KindAgent, KindModel, KindMCPServer, KindMCPClient, KindDataStore, KindService,
	KindIngress, KindWorkload, KindImage, KindNetworkRule, KindDependencies,
	KindApplication, KindActor, KindCapability,
}

var kindTitle = map[string]string{
	KindRoute: "Entry points (routes)", KindAgent: "AI agents", KindModel: "Models",
	KindMCPServer: "MCP servers", KindMCPClient: "MCP clients", KindDataStore: "Data stores",
	KindService: "External services", KindIngress: "Ingress", KindWorkload: "Workloads",
	KindImage: "Container images", KindNetworkRule: "Network rules", KindDependencies: "Dependencies",
	KindApplication: "Application", KindActor: "Actors", KindCapability: "Host capabilities reached",
}

func (m Model) elementByID() map[string]Element {
	out := make(map[string]Element, len(m.Elements))
	for _, e := range m.Elements {
		out[e.ID] = e
	}
	return out
}

// Terminal renders the short terminal summary.
func (m Model) Terminal() string {
	var b strings.Builder
	b.WriteString("Threat model: system evidence from your security scan\n\n")
	b.WriteString(ShortNotice + "\n\n")
	p := m.Provenance
	fmt.Fprintf(&b, "Based on a scan by nox %s on %s", p.ScanToolVersion, p.ScanGeneratedAt)
	if p.Commit != "" {
		fmt.Fprintf(&b, ", repository at %s", shortCommit(p.Commit))
	}
	names := make([]string, len(p.Artifacts))
	for i, a := range p.Artifacts {
		names[i] = a.Name
	}
	b.WriteString(".\nEvidence read: " + strings.Join(names, ", ") + "\n\n")

	counts := map[string]int{}
	for _, e := range m.Elements {
		counts[e.Kind]++
	}
	b.WriteString("Elements nox can evidence:\n")
	for _, k := range kindOrder {
		if counts[k] > 0 && k != KindApplication {
			fmt.Fprintf(&b, "  %-26s %d\n", kindTitle[k], counts[k])
		}
	}
	if len(m.Elements) == 0 {
		b.WriteString("  none: the scan outputs hold nothing this model can describe\n")
	}
	fmt.Fprintf(&b, "\nData flows: %d, crossing %d trust boundaries", len(m.Flows), len(m.Boundaries))
	if len(m.Boundaries) > 0 {
		b.WriteString(":\n")
		for _, bd := range m.Boundaries {
			fmt.Fprintf(&b, "  %s (%d)\n", bd.Label, bd.Flows)
		}
	} else {
		b.WriteString("\n")
	}
	s := m.Summary
	fmt.Fprintf(&b, "\nSTRIDE cells: %d with open issues, %d with leads to verify, %d with context only, %d not evidenced.\n",
		s.OpenIssues, s.LeadsToVerify, s.LimitedEvidence, s.NotEvidenced)
	if s.UnattributedFindings > 0 {
		fmt.Fprintf(&b, "%d active finding(s) belong to no modelled element; they are in findings.json.\n", s.UnattributedFindings)
	}
	fmt.Fprintf(&b, "Questions for the team: %d. What nox cannot see: %d limits listed in the written model.\n", s.Questions, len(m.Limits))
	if m.Changes != nil {
		b.WriteString("\n" + m.Changes.Terminal())
	}
	return b.String()
}

func shortCommit(c string) string {
	if len(c) > 12 {
		return c[:12]
	}
	return c
}

// Terminal renders the delta for the terminal.
func (d Delta) Terminal() string {
	var b strings.Builder
	b.WriteString("Changes since the previous model")
	if d.PreviousScanGeneratedAt != "" {
		b.WriteString(" (scan of " + d.PreviousScanGeneratedAt + ")")
	}
	b.WriteString(":\n")
	if d.Empty() {
		b.WriteString("  nothing changed in what could be compared\n")
	}
	for _, e := range d.ElementsAdded {
		fmt.Fprintf(&b, "  new %s: %s\n", kindWord(e.Kind), e.Name)
	}
	for _, e := range d.ElementsRemoved {
		fmt.Fprintf(&b, "  no longer evidenced, %s: %s\n", kindWord(e.Kind), e.Name)
	}
	for _, c := range d.PropertiesChanged {
		verb := "weakened"
		if c.Direction == infra.Stronger {
			verb = "strengthened"
		}
		fmt.Fprintf(&b, "  %s: %s\n", verb, c.Line())
	}
	for _, x := range d.BoundariesAdded {
		fmt.Fprintf(&b, "  new trust boundary: %s\n", x.Label)
	}
	for _, x := range d.BoundariesRemoved {
		fmt.Fprintf(&b, "  trust boundary no longer evidenced: %s\n", x.Label)
	}
	for _, f := range d.FlowsAdded {
		fmt.Fprintf(&b, "  new flow: %s → %s: %s\n", f.From, f.To, f.Label)
	}
	for _, f := range d.FlowsRemoved {
		fmt.Fprintf(&b, "  flow no longer evidenced: %s → %s: %s\n", f.From, f.To, f.Label)
	}
	for _, c := range d.CellsChanged {
		fmt.Fprintf(&b, "  %s / %s: %s -> %s\n", c.Name, c.Category.Label(), statusLabel(c.From), statusLabel(c.To))
		for _, a := range c.Added {
			b.WriteString("      + " + a + "\n")
		}
		for _, r := range c.Removed {
			b.WriteString("      - " + r + "\n")
		}
	}
	for _, c := range d.Caveats {
		b.WriteString("  note: " + c + "\n")
	}
	return b.String()
}

func kindWord(kind string) string {
	switch kind {
	case KindRoute:
		return "entry point"
	case KindAgent:
		return "AI agent"
	case KindMCPServer:
		return "MCP server"
	case KindMCPClient:
		return "MCP client"
	case KindModel:
		return "model"
	case KindDataStore:
		return "data store"
	case KindService:
		return "external service"
	case KindIngress:
		return "ingress"
	case KindWorkload:
		return "workload"
	case KindImage:
		return "container image"
	case KindNetworkRule:
		return "network rule"
	case KindDependencies:
		return "dependency set"
	}
	return kind
}

// Markdown renders the reviewer-facing model. With diagram set it includes a
// Mermaid data-flow diagram.
func (m Model) Markdown(diagram bool) string {
	var b strings.Builder
	b.WriteString("# Threat model: system evidence from a nox scan\n\n")
	fmt.Fprintf(&b, "> %s\n\n", m.Notice)
	m.writeProvenance(&b)
	m.writeSummary(&b)
	if m.Changes != nil {
		m.writeChanges(&b)
	}
	m.writeElements(&b)
	m.writeFlows(&b, diagram)
	m.writeSTRIDE(&b)
	m.writeQuestions(&b)
	m.writeLimits(&b)
	return b.String()
}

func (m Model) writeProvenance(b *strings.Builder) {
	p := m.Provenance
	b.WriteString("## What this was built from\n\n")
	fmt.Fprintf(b, "- Scan: nox %s, generated %s", p.ScanToolVersion, p.ScanGeneratedAt)
	if p.ScanOffline {
		b.WriteString(", offline")
	}
	b.WriteString("\n")
	if p.Commit != "" {
		fmt.Fprintf(b, "- Repository revision when this model was written: `%s` (the scan may have run at an earlier one)\n", p.Commit)
	}
	fmt.Fprintf(b, "- Scopes scanned: %s\n", strings.Join(p.ScopesScanned, ", "))
	if len(p.ScopesNotScanned) > 0 {
		fmt.Fprintf(b, "- Scopes not scanned: %s\n", strings.Join(p.ScopesNotScanned, ", "))
	}
	for _, a := range p.Artifacts {
		fmt.Fprintf(b, "- `%s` (%s), SHA-256 `%s`\n", a.Name, a.Kind, a.SHA256)
	}
	cov := func(ok bool) string {
		if ok {
			return "read"
		}
		return "not available"
	}
	fmt.Fprintf(b, "- Routes: %s; AI inventory: %s; SBOM: %s\n\n", cov(p.Coverage.Routes), cov(p.Coverage.AIInventory), cov(p.Coverage.SBOM))
}

func (m Model) writeSummary(b *strings.Builder) {
	s := m.Summary
	b.WriteString("## Summary\n\n")
	fmt.Fprintf(b, "- %d elements, %d data flows, %d trust boundaries\n", s.Elements, s.Flows, s.Boundaries)
	fmt.Fprintf(b, "- STRIDE cells: %d open issues, %d leads to verify, %d context only, %d not evidenced\n",
		s.OpenIssues, s.LeadsToVerify, s.LimitedEvidence, s.NotEvidenced)
	if s.UnattributedFindings > 0 {
		fmt.Fprintf(b, "- %d active finding(s) belong to no modelled element; see `findings.json`\n", s.UnattributedFindings)
	}
	fmt.Fprintf(b, "- %d questions for the team\n\n", s.Questions)
}

func (m Model) writeChanges(b *strings.Builder) {
	b.WriteString("## Changes since the previous model\n\n")
	b.WriteString("```\n" + strings.TrimRight(m.Changes.Terminal(), "\n") + "\n```\n\n")
}

func (m Model) writeElements(b *strings.Builder) {
	b.WriteString("## System elements\n\n")
	if len(m.Elements) == 0 {
		b.WriteString("The scan outputs hold nothing this model can describe as an element. See the limits below before reading that as an empty system.\n\n")
		return
	}
	by := map[string][]Element{}
	for _, e := range m.Elements {
		by[e.Kind] = append(by[e.Kind], e)
	}
	for _, k := range kindOrder {
		list := by[k]
		if len(list) == 0 || k == KindApplication {
			continue
		}
		fmt.Fprintf(b, "### %s\n\n| Element | Where | Notes |\n|---|---|---|\n", kindTitle[k])
		for _, e := range list {
			fmt.Fprintf(b, "| %s | %s | %s |\n", esc(e.Name), esc(codeOrDash(e.Location)), esc(elementNotes(e)))
		}
		b.WriteString("\n")
	}
}

func codeOrDash(s string) string {
	if s == "" {
		return "-"
	}
	return "`" + s + "`"
}

// elementNotes summarises an element's attributes in a fixed order.
func elementNotes(e Element) string {
	var parts []string
	for _, k := range []string{
		"authentication_middleware", "authorization_middleware", "authorization_lead",
		"tools", "command", "args", "provider", "pinned", "credential_env_var", "basis", "resource",
	} {
		if v := e.Attributes[k]; v != "" {
			parts = append(parts, strings.ReplaceAll(k, "_", " ")+": "+v)
		}
	}
	if len(e.Properties) > 0 {
		keys := make([]string, 0, len(e.Properties))
		for k := range e.Properties {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		var props []string
		for _, k := range keys {
			props = append(props, infra.Label(k)+" "+e.Properties[k])
		}
		parts = append(parts, strings.Join(props, ", "))
	}
	if len(parts) == 0 && len(e.Evidence) > 0 {
		return e.Evidence[0].Statement
	}
	return strings.Join(parts, "; ")
}

func esc(s string) string {
	s = strings.ReplaceAll(s, "|", "\\|")
	return strings.ReplaceAll(s, "\n", " ")
}

func (m Model) writeFlows(b *strings.Builder, diagram bool) {
	b.WriteString("## Data flows and trust boundaries\n\n")
	if len(m.Flows) == 0 {
		b.WriteString("No flow is evidenced by this scan.\n\n")
		return
	}
	b.WriteString("| Trust boundary | Flows |\n|---|---|\n")
	for _, bd := range m.Boundaries {
		fmt.Fprintf(b, "| %s (`%s`) | %d |\n", esc(bd.Label), bd.ID, bd.Flows)
	}
	b.WriteString("\n")
	els := m.elementByID()
	for _, bd := range m.Boundaries {
		fmt.Fprintf(b, "### %s\n\n", bd.Label)
		for _, f := range m.Flows {
			if f.Boundary != bd.ID {
				continue
			}
			fmt.Fprintf(b, "- %s → %s: %s\n", esc(els[f.From].Name), esc(els[f.To].Name), esc(f.Label))
			for _, ev := range f.Evidence {
				fmt.Fprintf(b, "  - evidence: %s\n", evidenceLine(ev))
			}
		}
		b.WriteString("\n")
	}
	if diagram {
		b.WriteString("### Diagram\n\n```mermaid\n" + m.Mermaid() + "```\n\n")
	}
}

func evidenceLine(ev Evidence) string {
	var s strings.Builder
	s.WriteString(ev.Statement)
	if ev.Count > 1 {
		s.WriteString(" (" + strconv.Itoa(ev.Count) + " findings)")
	}
	if ev.Waived {
		s.WriteString(" [waived]")
	}
	if ev.Ref != "" {
		s.WriteString(" (`" + ev.Ref + "`, " + ev.Artifact + ")")
	} else {
		s.WriteString(" (" + ev.Artifact + ")")
	}
	return s.String()
}

// Mermaid renders the flows as a Mermaid flowchart. Node identifiers are
// assigned in element-ID order and edges follow flow-ID order, so the diagram
// is byte-identical for identical evidence.
func (m Model) Mermaid() string {
	els := m.elementByID()
	used := map[string]bool{}
	for _, f := range m.Flows {
		used[f.From], used[f.To] = true, true
	}
	ids := make([]string, 0, len(used))
	for id := range used {
		if _, ok := els[id]; ok {
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	node := map[string]string{}
	for i, id := range ids {
		node[id] = "n" + strconv.Itoa(i+1)
	}
	zoneOrder := []Zone{ZoneUntrusted, ZoneApplication, ZoneModel, ZoneHost, ZoneData, ZoneThirdParty, ZoneDeploy}
	var b strings.Builder
	b.WriteString("flowchart LR\n")
	for _, z := range zoneOrder {
		var members []string
		for _, id := range ids {
			if els[id].Zone == z {
				members = append(members, id)
			}
		}
		if len(members) == 0 {
			continue
		}
		fmt.Fprintf(&b, "  subgraph %s[\"%s\"]\n", "z_"+string(z), zoneTitle(z))
		for _, id := range members {
			fmt.Fprintf(&b, "    %s[\"%s\"]\n", node[id], mermaidText(els[id].Name))
		}
		b.WriteString("  end\n")
	}
	for _, f := range m.Flows {
		from, okF := node[f.From]
		to, okT := node[f.To]
		if !okF || !okT {
			continue
		}
		fmt.Fprintf(&b, "  %s -->|\"%s\"| %s\n", from, mermaidText(f.Boundary), to)
	}
	return b.String()
}

func zoneTitle(z Zone) string {
	switch z {
	case ZoneUntrusted:
		return "Untrusted"
	case ZoneApplication:
		return "Application"
	case ZoneModel:
		return "Model provider"
	case ZoneHost:
		return "Host effects"
	case ZoneData:
		return "Data stores"
	case ZoneThirdParty:
		return "Third parties"
	case ZoneDeploy:
		return "Deployment"
	}
	return string(z)
}

func mermaidText(s string) string {
	s = strings.ReplaceAll(s, `"`, "'")
	s = strings.ReplaceAll(s, "<", "(")
	s = strings.ReplaceAll(s, ">", ")")
	return strings.ReplaceAll(s, "\n", " ")
}

func cellCode(c Cell) string {
	switch c.Status {
	case OpenIssues:
		return "open " + strconv.Itoa(c.Findings)
	case LeadsToVerify:
		return "lead"
	case LimitedEvidence:
		return "context"
	}
	return "none"
}

func (m Model) writeSTRIDE(b *strings.Builder) {
	b.WriteString("## STRIDE by element\n\n")
	b.WriteString("Each cell holds the evidence nox has for one element and one category. `open N` is N active findings; `lead` is something worth checking that is not a finding; `context` is evidence that describes the element without anything open; `none` means **nox has no evidence either way**.\n\n")
	if len(m.STRIDE) == 0 {
		b.WriteString("No element is assessed.\n\n")
		return
	}
	els := m.elementByID()
	b.WriteString("| Element | S | T | R | I | D | E |\n|---|---|---|---|---|---|---|\n")
	for _, r := range m.STRIDE {
		fmt.Fprintf(b, "| %s", esc(els[r.Element].Name))
		for _, c := range r.Cells {
			b.WriteString(" | " + cellCode(c))
		}
		b.WriteString(" |\n")
	}
	b.WriteString("\n")
	for _, r := range m.STRIDE {
		var lines []string
		for _, c := range r.Cells {
			if len(c.Evidence) == 0 {
				continue
			}
			lines = append(lines, fmt.Sprintf("- **%s** (%s)", c.Category.Label(), strings.ToLower(statusLabel(c.Status))))
			for _, ev := range c.Evidence {
				lines = append(lines, "  - "+evidenceLine(ev))
			}
		}
		if len(r.Other) > 0 {
			lines = append(lines, "- **Findings with no STRIDE category** (the weakness they declare is not one this mapping covers)")
			for _, ev := range r.Other {
				lines = append(lines, "  - "+evidenceLine(ev))
			}
		}
		if len(lines) == 0 {
			continue
		}
		e := els[r.Element]
		fmt.Fprintf(b, "### %s\n\n`%s`. Categories not listed: nox has no evidence either way.\n\n%s\n\n", e.Name, e.ID, strings.Join(lines, "\n"))
	}
}

func (m Model) writeQuestions(b *strings.Builder) {
	b.WriteString("## Questions for the team\n\n")
	if len(m.Questions) == 0 {
		b.WriteString("The evidence raises no question. That reflects how little the scan could see; read the limits below.\n\n")
		return
	}
	b.WriteString("Each question comes from a gap in the evidence, not from a judgement that something is wrong.\n\n")
	for _, q := range m.Questions {
		fmt.Fprintf(b, "%s. %s\n", strings.TrimPrefix(q.ID, "Q"), q.Question)
	}
	b.WriteString("\n")
}

func (m Model) writeLimits(b *strings.Builder) {
	b.WriteString("## What nox cannot see\n\n")
	for _, l := range m.Limits {
		b.WriteString("- " + l + "\n")
	}
	b.WriteString("\n")
}
