package threatmodel

import (
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/nox-hq/nox/core/analyzers/ai"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/infra"
)

// Artifact names used in evidence. They are the base names a scan writes, and
// the evidence says which output a claim comes from.
const (
	artFindings  = "findings.json"
	artInventory = "ai.inventory.json"
	artSBOM      = "sbom"
)

// obs is something nox records about an element that is not a finding: the
// middleware on a route, the capabilities an agent holds. It becomes evidence
// in a STRIDE cell.
type obs struct {
	cat    Category
	status Status
	ev     Evidence
}

// span is one place a route is registered.
type span struct {
	file string
	line int
}

// elem is an Element under construction, with the private indexes the model
// uses to attach findings to it.
type elem struct {
	Element
	files map[string]bool
	spans []span
	obs   []obs
	// exposedBy holds the findings that say the element is reachable from
	// outside, which become an exposure flow from the internet.
	exposedBy []Evidence
	// toolNames and toolCaps are an agent's tools and their capability tags,
	// kept for building flows.
	toolNames []string
	toolCaps  map[string][]string
	// infra is set on an element derived from an infrastructure rule.
	infra *iacRow
	// resource is set on an element derived from the deployment inventory.
	resource *infra.Resource
}

// builder accumulates the model.
type builder struct {
	in     Input
	active []findings.Finding
	waived []findings.Finding
	elems  map[string]*elem
	flows  map[string]*Flow
	// infraPerFile counts the infrastructure elements derived from each file.
	infraPerFile map[string]int
	// resources are the inventory's elements by file, in declaration order.
	resources map[string][]*elem
}

func newBuilder(in Input) *builder {
	b := &builder{in: in, elems: map[string]*elem{}, flows: map[string]*Flow{}, infraPerFile: map[string]int{}, resources: map[string][]*elem{}}
	for _, f := range in.Report.Findings {
		if f.Status.IsActive() {
			b.active = append(b.active, f)
		} else {
			b.waived = append(b.waived, f)
		}
	}
	return b
}

func loc(path string, line int) string {
	if line > 0 {
		return path + ":" + strconv.Itoa(line)
	}
	return path
}

// add creates the element or, when it already exists, merges evidence into it.
func (b *builder) add(e Element, files ...string) *elem {
	cur, ok := b.elems[e.ID]
	if !ok {
		cur = &elem{Element: e, files: map[string]bool{}}
		if cur.Attributes == nil {
			cur.Attributes = map[string]string{}
		}
		b.elems[e.ID] = cur
	} else {
		for _, ev := range e.Evidence {
			if !hasEvidence(cur.Evidence, ev) {
				cur.Evidence = append(cur.Evidence, ev)
			}
		}
		for k, v := range e.Attributes {
			if _, set := cur.Attributes[k]; !set {
				cur.Attributes[k] = v
			}
		}
	}
	for _, f := range files {
		if f != "" {
			cur.files[f] = true
		}
	}
	return cur
}

func hasEvidence(list []Evidence, ev Evidence) bool {
	for _, x := range list {
		if x == ev {
			return true
		}
	}
	return false
}

// findingEvidence turns a group of findings that share a rule and a file into
// one piece of evidence.
func findingEvidence(group []findings.Finding, waived bool) Evidence {
	first := group[0]
	sev := first.Severity
	for _, f := range group[1:] {
		if sevRank(f.Severity) < sevRank(sev) {
			sev = f.Severity
		}
	}
	return Evidence{
		Artifact:  artFindings,
		Ref:       loc(first.Location.FilePath, first.Location.StartLine),
		Statement: first.RuleID + ": " + first.Message,
		RuleID:    first.RuleID,
		Severity:  string(sev),
		Count:     len(group),
		Waived:    waived,
	}
}

func sevRank(s findings.Severity) int {
	switch s {
	case findings.SeverityCritical:
		return 0
	case findings.SeverityHigh:
		return 1
	case findings.SeverityMedium:
		return 2
	case findings.SeverityLow:
		return 3
	}
	return 4
}

// groupFindings groups findings by rule and file, in a stable order.
func groupFindings(ff []findings.Finding, waived bool) []Evidence {
	type key struct{ rule, file string }
	groups := map[key][]findings.Finding{}
	var keys []key
	for _, f := range ff {
		k := key{f.RuleID, f.Location.FilePath}
		if _, ok := groups[k]; !ok {
			keys = append(keys, k)
		}
		groups[k] = append(groups[k], f)
	}
	out := make([]Evidence, 0, len(keys))
	for _, k := range keys {
		g := groups[k]
		sort.SliceStable(g, func(i, j int) bool {
			if g[i].Location.StartLine != g[j].Location.StartLine {
				return g[i].Location.StartLine < g[j].Location.StartLine
			}
			return g[i].Fingerprint < g[j].Fingerprint
		})
		out = append(out, findingEvidence(g, waived))
	}
	sortEvidence(out)
	return out
}

func sortEvidence(ev []Evidence) {
	sort.SliceStable(ev, func(i, j int) bool {
		a, b := ev[i], ev[j]
		if a.Waived != b.Waived {
			return !a.Waived
		}
		if a.Severity != b.Severity {
			return sevRank(findings.Severity(a.Severity)) < sevRank(findings.Severity(b.Severity))
		}
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Ref != b.Ref {
			return a.Ref < b.Ref
		}
		return a.Statement < b.Statement
	})
}

// ---------------------------------------------------------------------------
// Elements
// ---------------------------------------------------------------------------

var structuralResource = regexp.MustCompile(`resource "([^"]+)" \(([A-Za-z]+)\)`)

func (b *builder) collect() {
	b.collectRoutes()
	b.collectInventory()
	b.collectDependencies()
	b.collectInfrastructure()
	b.collectApplication()
}

func (b *builder) collectRoutes() {
	rep := b.in.Report
	for _, r := range rep.Routes {
		name := r.Method + " " + r.Path
		e := b.add(Element{
			ID: "route:" + name, Kind: KindRoute, Name: name, Zone: ZoneApplication,
			Location: loc(r.FilePath, r.Line),
			Attributes: map[string]string{
				"method": r.Method, "path": r.Path,
			},
			Evidence: []Evidence{{
				Artifact: artFindings, Ref: loc(r.FilePath, r.Line),
				Statement: routeStatement(r.Reader, r.FilePath),
			}},
		}, r.FilePath)
		e.spans = append(e.spans, span{r.FilePath, r.Line})
		if r.Authn != "" {
			e.Attributes["authentication_middleware"] = r.Authn
			e.obs = append(e.obs, obs{Spoofing, LimitedEvidence, Evidence{
				Artifact: artFindings, Ref: loc(r.FilePath, r.Line),
				Statement: "authentication middleware `" + r.Authn + "` is on the route's chain; nox reads middleware by name and does not evaluate that it works",
			}})
		} else {
			e.Attributes["authentication_middleware"] = "none visible"
			e.obs = append(e.obs, obs{Spoofing, LeadsToVerify, Evidence{
				Artifact: artFindings, Ref: loc(r.FilePath, r.Line),
				Statement: "no authentication middleware is visible on the route's chain; this is a route that is either public on purpose or checks the caller somewhere nox does not read",
			}})
		}
		if r.Authz != "" {
			e.Attributes["authorization_middleware"] = r.Authz
			e.obs = append(e.obs, obs{ElevationOfPrivilege, LimitedEvidence, Evidence{
				Artifact: artFindings, Ref: loc(r.FilePath, r.Line),
				Statement: "authorization or record-loading middleware `" + r.Authz + "` is on the route's chain; nox does not evaluate what it checks",
			}})
		}
	}
	for _, l := range rep.Leads {
		id := "route:" + l.Route
		e, ok := b.elems[id]
		if !ok {
			// A findings.json written before routes were recorded still names
			// the routes its leads are about, and a lead is evidence the route
			// exists.
			e = b.add(Element{
				ID: id, Kind: KindRoute, Name: l.Route, Zone: ZoneApplication,
				Location: loc(l.FilePath, l.Line),
				Attributes: map[string]string{
					"authentication_middleware": "not recorded",
				},
				Evidence: []Evidence{{
					Artifact: artFindings, Ref: loc(l.FilePath, l.Line),
					Statement: "route named by an authorization lead",
				}},
			}, l.FilePath)
			e.spans = append(e.spans, span{l.FilePath, l.Line})
		}
		e.files[l.FilePath] = true
		if l.Category == "authentication" {
			// The route's own "no authentication middleware visible" is this
			// same fact, read from the same inventory; saying it twice would
			// count one observation as two.
			e.Attributes["authentication_lead"] = "yes"
			if !ok {
				// A findings.json that did not record routes: the lead is the
				// only evidence there is.
				e.obs = append(e.obs, obs{Spoofing, LeadsToVerify, Evidence{
					Artifact: artFindings, Ref: loc(l.FilePath, l.Line), RuleID: l.RuleID,
					Statement: "lead: " + l.Route + " " + l.Statement + ". " + l.Test,
				}})
			}
			continue
		}
		ev := Evidence{
			Artifact: artFindings, Ref: loc(l.FilePath, l.Line), RuleID: l.RuleID,
			Statement: "lead: " + l.Route + " " + l.Statement + ". " + l.Test,
		}
		e.obs = append(e.obs,
			obs{ElevationOfPrivilege, LeadsToVerify, ev},
			obs{InformationDisclosure, LeadsToVerify, ev},
		)
		e.Attributes["authorization_lead"] = "yes"
	}
}

func (b *builder) collectInventory() {
	inv := b.in.Inventory
	if inv == nil {
		return
	}
	for _, set := range inv.ToolMatrix {
		if set.Server != "" {
			b.addMCPServer(set.Server, set.Path, set.Tools, nil)
			continue
		}
		b.addAgent(set)
	}
	for _, c := range inv.Components {
		if c.Type == "mcp_server" {
			b.addMCPServer(c.Name, c.Path, nil, c.Details)
		}
	}
	for _, m := range inv.ModelProvenance {
		b.addModel(m)
	}
}

func (b *builder) addAgent(set ai.ToolPermissionSet) {
	id := "agent:" + set.Path
	if set.Agent != "" && set.Agent != baseName(set.Path) {
		id += "#" + set.Agent
	}
	tools := append([]string(nil), set.Tools...)
	sort.Strings(tools)
	var described, unclassified []string
	for _, t := range tools {
		caps := append([]string(nil), set.Capabilities[t]...)
		sort.Strings(caps)
		if len(caps) == 0 {
			unclassified = append(unclassified, t)
			described = append(described, t+" (capability not classified)")
			continue
		}
		described = append(described, t+" ("+strings.Join(caps, ", ")+")")
	}
	ref := set.Path
	e := b.add(Element{
		ID: id, Kind: KindAgent, Name: set.Agent, Zone: ZoneApplication, Location: ref,
		Attributes: map[string]string{
			"agent": set.Agent, "tools": strings.Join(described, "; "),
		},
		Evidence: []Evidence{{
			Artifact: artInventory, Ref: ref,
			Statement: "agent exposes " + strconv.Itoa(len(tools)) + " tool(s) to the model: " + strings.Join(described, "; "),
		}},
	}, set.Path)
	if len(unclassified) > 0 {
		e.Attributes["unclassified_tools"] = strings.Join(unclassified, ", ")
	}
	e.obs = append(e.obs, obs{ElevationOfPrivilege, LimitedEvidence, Evidence{
		Artifact: artInventory, Ref: ref,
		Statement: "the agent exposes these tools to the model: " + strings.Join(described, "; "),
	}})
	e.toolNames = tools
	e.toolCaps = set.Capabilities
}

func (b *builder) addMCPServer(server, path string, tools []string, details map[string]string) {
	clientID := "mcp-client:" + path
	b.add(Element{
		ID: clientID, Kind: KindMCPClient, Name: "MCP client configured by " + path, Zone: ZoneApplication,
		Location: path,
		Evidence: []Evidence{{
			Artifact: artInventory, Ref: path,
			Statement: "MCP configuration file naming the servers an agent runtime launches",
		}},
	}, path)
	id := "mcp:" + server + "@" + path
	attrs := map[string]string{"server": server}
	for _, k := range []string{"command", "args", "transport"} {
		if v := details[k]; v != "" {
			attrs[k] = v
		}
	}
	e := b.add(Element{
		ID: id, Kind: KindMCPServer, Name: "MCP server " + server, Zone: ZoneThirdParty, Location: path,
		Attributes: attrs,
		Evidence: []Evidence{{
			Artifact: artInventory, Ref: path,
			Statement: "MCP server `" + server + "` is configured" + launchSuffix(attrs),
		}},
	}, path)
	if len(tools) > 0 {
		e.Attributes["tools"] = strings.Join(tools, ", ")
		for _, t := range tools {
			if t == "*" {
				e.obs = append(e.obs, obs{ElevationOfPrivilege, LimitedEvidence, Evidence{
					Artifact: artInventory, Ref: path,
					Statement: "the configuration does not limit which of the server's tools the client may call (tool list `*`)",
				}})
				break
			}
		}
	}
	b.mcpObservations(e, path)
}

func launchSuffix(attrs map[string]string) string {
	if attrs["command"] == "" {
		return ""
	}
	return ", launched as `" + strings.TrimSpace(attrs["command"]+" "+attrs["args"]) + "`"
}

// pinnedVersion matches a package argument carrying a version: name@1.2.3 or
// name==1.2.3.
var pinnedVersion = regexp.MustCompile(`(?:@|==)\d`)

// mcpObservations records what the launch command alone shows. It reads the
// command line the configuration holds and nothing about the server.
func (b *builder) mcpObservations(e *elem, path string) {
	cmd, args := e.Attributes["command"], strings.Fields(e.Attributes["args"])
	if cmd == "" {
		return
	}
	switch cmd {
	case "npx", "uvx", "bunx", "pipx":
		var pkg string
		for _, a := range args {
			if !strings.HasPrefix(a, "-") {
				pkg = a
				break
			}
		}
		if pkg != "" && !pinnedVersion.MatchString(pkg) {
			e.obs = append(e.obs, obs{Tampering, LimitedEvidence, Evidence{
				Artifact: artInventory, Ref: path,
				Statement: "launched with `" + cmd + "` from package `" + pkg + "` with no version pinned, so what runs is whatever the registry serves at launch",
			}})
		}
	}
	for _, a := range args {
		if a == "/" {
			e.obs = append(e.obs, obs{InformationDisclosure, LimitedEvidence, Evidence{
				Artifact: artInventory, Ref: path,
				Statement: "one launch argument is the filesystem root `/`",
			}})
			break
		}
	}
}

func baseName(p string) string {
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func (b *builder) addModel(m ai.ModelReference) {
	provider := m.Registry
	name := m.Name
	if provider != "" {
		name += " (" + provider + ")"
	}
	attrs := map[string]string{"model": m.Name}
	if provider != "" {
		attrs["provider"] = provider
	}
	attrs["pinned"] = strconv.FormatBool(m.Pinned)
	if m.AuthEnvVar != "" {
		attrs["credential_env_var"] = m.AuthEnvVar
	}
	if m.License != "" {
		attrs["license"] = m.License
	}
	e := b.add(Element{
		ID: "model:" + m.Name + "@" + m.Path, Kind: KindModel, Name: name, Zone: ZoneModel,
		Location: loc(m.Path, m.Line), Attributes: attrs,
		Evidence: []Evidence{{
			Artifact: artInventory, Ref: loc(m.Path, m.Line),
			Statement: "model `" + m.Name + "` is referenced by the application code",
		}},
	}, m.Path)
	if !m.Pinned {
		e.obs = append(e.obs, obs{Tampering, LimitedEvidence, Evidence{
			Artifact: artInventory, Ref: loc(m.Path, m.Line),
			Statement: "the model reference is not pinned to a revision, so the provider may change its behaviour without a change here",
		}})
	}
	if m.AuthEnvVar != "" {
		e.obs = append(e.obs, obs{Spoofing, LimitedEvidence, Evidence{
			Artifact: artInventory, Ref: loc(m.Path, m.Line),
			Statement: "the call authenticates with the credential in environment variable `" + m.AuthEnvVar + "`; where it is stored and who can read it is outside the scan",
		}})
	}
}

func (b *builder) collectDependencies() {
	sb := b.in.SBOM
	supply := b.supplyChainFindings()
	if sb == nil && len(supply) == 0 {
		return
	}
	if sb != nil {
		seen := map[string]bool{}
		for _, c := range sb.Components {
			row, ok := matchDependency(c.Name)
			if !ok {
				continue
			}
			ev := Evidence{
				Artifact: sb.Name, Ref: c.Name + "@" + c.Version,
				Statement: "package " + c.Name + "@" + c.Version + " is in the dependency set; the SBOM does not say whether it is direct or transitive",
			}
			switch row.class {
			case depStore:
				b.add(Element{ID: "store:" + row.id, Kind: KindDataStore, Name: row.name, Zone: ZoneData,
					Attributes: map[string]string{"basis": "dependency"}, Evidence: []Evidence{ev}})
			case depService:
				b.add(Element{ID: "service:" + row.id, Kind: KindService, Name: row.name, Zone: ZoneThirdParty,
					Attributes: map[string]string{"basis": "dependency"}, Evidence: []Evidence{ev}})
			case depAIProvider:
				if b.modelFromProvider(row.provider) {
					continue
				}
				b.add(Element{ID: "service:" + row.id, Kind: KindService, Name: row.name, Zone: ZoneThirdParty,
					Attributes: map[string]string{"basis": "dependency"}, Evidence: []Evidence{ev}})
			}
			seen[c.Name] = true
		}
		b.add(Element{
			ID: "dependencies", Kind: KindDependencies, Zone: ZoneApplication,
			Name:       "Third-party dependencies (" + strconv.Itoa(len(sb.Components)) + " packages)",
			Attributes: map[string]string{"packages": strconv.Itoa(len(sb.Components)), "sbom": sb.Format},
			Evidence:   []Evidence{{Artifact: sb.Name, Statement: strconv.Itoa(len(sb.Components)) + " packages in " + sb.Format}},
		})
		return
	}
	b.add(Element{
		ID: "dependencies", Kind: KindDependencies, Zone: ZoneApplication, Name: "Third-party dependencies",
		Evidence: []Evidence{{Artifact: artFindings, Statement: "dependency findings exist; no SBOM was provided"}},
	})
}

// modelFromProvider reports whether the AI inventory already names a model
// from the provider, in which case the provider is that model's element and is
// not listed twice.
func (b *builder) modelFromProvider(provider string) bool {
	for _, e := range b.elems {
		if e.Kind == KindModel && strings.EqualFold(e.Attributes["provider"], provider) {
			return true
		}
	}
	return false
}

func isSupplyChainRule(id string) bool {
	for _, p := range supplyChainPrefixes {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}

func (b *builder) supplyChainFindings() []findings.Finding {
	var out []findings.Finding
	for _, f := range append(append([]findings.Finding(nil), b.active...), b.waived...) {
		if isSupplyChainRule(f.RuleID) {
			out = append(out, f)
		}
	}
	return out
}

func (b *builder) collectInfrastructure() {
	b.collectResources()
	all := append(append([]findings.Finding(nil), b.active...), b.waived...)
	sort.SliceStable(all, func(i, j int) bool {
		if all[i].Location.FilePath != all[j].Location.FilePath {
			return all[i].Location.FilePath < all[j].Location.FilePath
		}
		if all[i].Location.StartLine != all[j].Location.StartLine {
			return all[i].Location.StartLine < all[j].Location.StartLine
		}
		return all[i].RuleID < all[j].RuleID
	})
	type group struct {
		row  iacRow
		file string
		ff   []findings.Finding
	}
	groups := map[string]*group{}
	var order []string
	for _, f := range all {
		row, ok := iacRules[f.RuleID]
		if !ok || b.resourceFor(f) != nil {
			continue
		}
		key := row.kind + "|" + row.sub + "|" + f.Location.FilePath
		g, ok := groups[key]
		if !ok {
			g = &group{row: row, file: f.Location.FilePath}
			groups[key] = g
			order = append(order, key)
		}
		g.ff = append(g.ff, f)
	}
	for _, key := range order {
		g := groups[key]
		name := infraNaming(g.row, g.file, g.ff)
		idKind := g.row.kind
		if g.row.sub != "" {
			idKind = g.row.sub
		}
		zone := ZoneDeploy
		if g.row.kind == KindDataStore {
			zone = ZoneData
		}
		e := b.add(Element{
			ID: "deploy:" + idKind + "@" + g.file, Kind: g.row.kind, Name: name, Zone: zone,
			Location: loc(g.file, g.ff[0].Location.StartLine),
			Attributes: map[string]string{
				"file": g.file,
			},
			Evidence: groupFindings(g.ff, false),
		}, g.file)
		row := g.row
		e.infra = &row
		b.infraPerFile[g.file]++
		for _, f := range g.ff {
			if row := iacRules[f.RuleID]; row.exposes {
				e.exposedBy = append(e.exposedBy, findingEvidence([]findings.Finding{f}, !f.Status.IsActive()))
			}
		}
		if g.row.sub != "" {
			e.Attributes["resource"] = g.row.sub
		}
	}
}

// infraNaming names an infrastructure element from the structural claim a rule
// recorded ("the kubernetes resource "invoicely" (Ingress)") when it has one,
// and from its file otherwise.
func infraNaming(row iacRow, file string, ff []findings.Finding) string {
	label := map[string]string{
		KindIngress: "Ingress", KindWorkload: "Workload", KindImage: "Container image",
		KindNetworkRule: "Network rule", KindDataStore: "Data store",
	}[row.kind]
	switch row.sub {
	case "bucket":
		label = "Storage bucket"
	case "database":
		label = "Database instance"
	}
	for _, f := range ff {
		if m := structuralResource.FindStringSubmatch(f.Metadata["structural_claim"]); m != nil {
			return label + " " + m[1] + " (" + file + ")"
		}
	}
	return label + " (" + file + ")"
}

func (b *builder) collectApplication() {
	for _, e := range b.elems {
		switch e.Kind {
		case KindRoute, KindAgent, KindModel, KindMCPClient:
			b.add(Element{
				ID: "app", Kind: KindApplication, Name: "Application code", Zone: ZoneApplication,
				Evidence: []Evidence{{Artifact: artFindings, Statement: "the repository that was scanned"}},
			})
			return
		}
	}
	for _, e := range b.elems {
		if strings.HasPrefix(e.ID, "store:") || strings.HasPrefix(e.ID, "service:") {
			b.add(Element{
				ID: "app", Kind: KindApplication, Name: "Application code", Zone: ZoneApplication,
				Evidence: []Evidence{{Artifact: artFindings, Statement: "the repository that was scanned"}},
			})
			return
		}
	}
}

// routeFor returns the route registered at or above line in file: the route
// whose handler a finding on that line most plausibly sits in. It reads line
// order only, so a finding in a handler defined elsewhere is not attributed.
func (b *builder) routeFor(file string, line int) *elem {
	var best *elem
	bestLine := -1
	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		if e.Kind != KindRoute {
			continue
		}
		for _, s := range e.spans {
			if s.file == file && s.line <= line && s.line > bestLine {
				best, bestLine = e, s.line
			}
		}
	}
	return best
}

func sortedIDs(m map[string]*elem) []string {
	ids := make([]string, 0, len(m))
	for id := range m {
		ids = append(ids, id)
	}
	sort.Strings(ids)
	return ids
}

func (b *builder) ensureActor(id, name string) *elem {
	return b.add(Element{
		ID: id, Kind: KindActor, Name: name, Zone: ZoneUntrusted,
		Evidence: []Evidence{{Artifact: artFindings, Statement: "origin of untrusted input; present because a flow starts here"}},
	})
}

func (b *builder) ensureCapability(id, name string, ev Evidence) *elem {
	return b.add(Element{
		ID: "effect:" + id, Kind: KindCapability, Name: name, Zone: ZoneHost,
		Evidence: []Evidence{ev},
	})
}

// routeStatement says what read a route registration. It names the reader the
// route carries; a report written before routes carried one falls back to the
// file's language, which can only say so much.
func routeStatement(reader, file string) string {
	if reader != "" {
		return "route registration read by the " + reader + " reader"
	}
	if strings.HasSuffix(file, ".py") {
		return "route registration read by the authorization reader (Python)"
	}
	return "route registration read by the authorization reader (JavaScript or TypeScript)"
}
