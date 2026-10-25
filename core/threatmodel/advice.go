package threatmodel

import (
	"sort"
	"strconv"
	"strings"
)

// maxQuestionsPerKind bounds the questions one kind of gap raises. Past the
// bound a single question names how many more there are, so a service with two
// hundred routes does not bury the questions about its one shell tool.
const maxQuestionsPerKind = 12

// fixedLimits are what a repository scan can never show, whatever it found.
// They are stated in every model, first, because they decide how much a model
// built on this evidence can be trusted to be complete.
var fixedLimits = []string{
	"Business logic and intent. Nox cannot tell a route that is public on purpose from one that is unprotected by mistake, or a record that is shared by design from one that leaks.",
	"Runtime configuration: environment variables, feature flags, secret stores and anything set outside the repository.",
	"The identity provider, session handling and token validation behind authentication. Middleware is read by name; nox does not evaluate whether it works.",
	"Network topology beyond what infrastructure-as-code findings show: firewalls, service meshes, VPNs, peering, and what a load balancer actually forwards.",
	"Entry points. Routes are read only from Express, Fastify, Next.js and NestJS (JavaScript and TypeScript) and Flask, FastAPI and Django (Python), and authorization leads come from the same readers. Go, Java, Rails and other frameworks are not enumerated, and neither are gRPC services, queue consumers or scheduled jobs.",
	"Infrastructure. Only the resources nox reads from Terraform, CloudFormation, Kubernetes, Compose and Dockerfiles appear, with the properties it knows how to read. A resource of another kind, or one produced by a template or a module, is not in this model.",
	"Dependencies. Packages are known from the SBOM, which does not say whether a package is direct or transitive. A data store or service inferred from a package shows the application can reach it, not that it does.",
	"Data flows are static and name-level. A flow joins two elements because the scan connects them (the same file, a taint finding, a dependency, a configuration entry). Nox does not trace calls between routes, services and stores, and does not see data at rest or in transit.",
	"Data sensitivity. Nox attaches DATA-* findings to the element in the file they were found in; it does not classify what each store holds.",
	"Findings are attached to elements by file, and to a route by the nearest registration above them in the same file. A finding in a shared helper is attached to no route, and a finding in a file with no modelled element appears only in the unattributed count.",
	"STRIDE categories come from the weakness (CWE) a rule declares. A finding with no weakness, or with one the mapping does not cover, is listed apart from the table, not forced into a category.",
	"Third-party services, model providers and the contents of MCP servers are outside the scan.",
	"A cell with no evidence means nox has none. It does not mean there is nothing to find.",
}

// limits returns the fixed limits followed by those specific to this run.
func (b *builder) limits() []string {
	out := append([]string(nil), fixedLimits...)
	rep := b.in.Report
	if sc := rep.Meta.Scope; sc != nil && len(sc.NotScanned) > 0 {
		out = append(out, "This scan covered only "+strings.Join(sc.Scanned, ", ")+". It did not cover "+strings.Join(sc.NotScanned, ", ")+", so nothing in the model comes from those checks.")
	}
	if rep.Meta.Offline {
		out = append(out, "The scan ran offline, so known-vulnerability data was not looked up and dependency findings may be missing.")
	}
	n := 0
	for _, d := range rep.Meta.Degradations {
		if !d.Advisory {
			n++
		}
	}
	if n > 0 {
		out = append(out, strconv.Itoa(n)+" check(s) in the scan did not complete (see degradations in findings.json), so evidence from them is missing.")
	}
	if b.in.Inventory == nil {
		out = append(out, "No ai.inventory.json was provided, so AI agents, tools, models and MCP servers are not in the model. This is a gap, not an absence.")
	} else if len(b.in.Inventory.Checks) == 0 {
		out = append(out, "The AI inventory records no checks that ran, so an empty inventory means the AI analysis did not look.")
	}
	if b.in.SBOM == nil {
		out = append(out, "No SBOM was provided, so data stores and services inferred from dependencies are not in the model. This is a gap, not an absence.")
	}
	if len(rep.Routes) == 0 && len(rep.LeadChecks) > 0 {
		out = append(out, "This findings.json records authorization leads but no routes, so it was written before routes were recorded. Re-run `nox scan` to include them.")
	}
	if len(rep.Routes) == 0 && len(rep.LeadChecks) == 0 {
		out = append(out, "No routes were read, so the model has no HTTP entry points. That can mean the project has none, or that its framework is one nox does not read.")
	}
	return out
}

// questions derives what to ask the team from the gaps in the evidence. Each
// question names the thing it is about and cites why it is raised.
func (b *builder) questions() []Question {
	var qs []Question
	byKind := map[string][]Question{}
	add := func(kind string, q Question) {
		// Two elements can raise the same question, such as one model
		// referenced from several files. Asking it once is enough; the
		// elements themselves list every place.
		for _, have := range byKind[kind] {
			if have.Question == q.Question {
				return
			}
		}
		q.ID = kind + "|" + q.ID
		byKind[kind] = append(byKind[kind], q)
	}

	for _, id := range sortedIDs(b.elems) {
		e := b.elems[id]
		switch e.Kind {
		case KindAgent:
			b.agentQuestions(e, add)
		case KindMCPServer:
			desc := e.Name
			if cmd := strings.TrimSpace(e.Attributes["command"] + " " + e.Attributes["args"]); cmd != "" {
				desc += " (`" + cmd + "`)"
			}
			add("mcp-server", Question{
				ID: id, Element: id,
				Question: desc + " is configured in " + e.Location + ": who approves adding a server like this, and what can it reach on the machine that runs it?",
				Basis:    e.Evidence[0],
			})
		case KindRoute:
			b.routeQuestions(e, add)
		case KindIngress, KindDataStore, KindNetworkRule:
			if len(e.exposedBy) > 0 {
				add("exposure", Question{
					ID: id, Element: id,
					Question: e.Name + " is reachable from outside according to " + e.exposedBy[0].RuleID + ": is that intended, and who needs that access?",
					Basis:    e.exposedBy[0],
				})
			}
			if e.Kind == KindDataStore && e.Attributes["basis"] == "dependency" {
				add("data-store", Question{
					ID: id, Element: id,
					Question: "Which components may query " + e.Name + ", with which credentials and privileges?",
					Basis:    e.Evidence[0],
				})
			}
		case KindService:
			add("third-party", Question{
				ID: id, Element: id,
				Question: "What data does the application send to " + e.Name + ", and who holds its credentials?",
				Basis:    e.Evidence[0],
			})
		case KindModel:
			add("third-party", Question{
				ID: id, Element: id,
				Question: "What data reaches model " + e.Attributes["model"] + " in prompts, and is any of it data the application promises to keep private?",
				Basis:    e.Evidence[0],
			})
			if e.Attributes["pinned"] == "false" {
				add("model-pin", Question{
					ID: id, Element: id,
					Question: "Model " + e.Attributes["model"] + " is not pinned to a revision: who notices when the provider changes its behaviour?",
					Basis:    e.Evidence[0],
				})
			}
		}
	}
	if sc := b.in.Report.Meta.Scope; sc != nil && len(sc.NotScanned) > 0 {
		add("coverage", Question{
			ID:       "scope",
			Question: "The scan did not cover " + strings.Join(sc.NotScanned, ", ") + ": is that deliberate, and who looks at those areas?",
			Basis:    Evidence{Artifact: artFindings, Statement: "scan scope recorded in findings.json"},
		})
	}

	kinds := sortedKeys(byKind)
	for _, k := range kinds {
		list := byKind[k]
		sort.SliceStable(list, func(i, j int) bool { return list[i].ID < list[j].ID })
		if len(list) > maxQuestionsPerKind {
			rest := len(list) - maxQuestionsPerKind
			list = append(list[:maxQuestionsPerKind:maxQuestionsPerKind], Question{
				ID:       k + "|more",
				Question: strconv.Itoa(rest) + " more question(s) of this kind are in the model's elements; they were left out to keep the list readable.",
				Basis:    list[0].Basis,
			})
		}
		qs = append(qs, list...)
	}
	for i := range qs {
		qs[i].ID = "Q" + strconv.Itoa(i+1)
	}
	return qs
}

func (b *builder) agentQuestions(e *elem, add func(string, Question)) {
	name := e.Attributes["agent"]
	for _, t := range e.toolNames {
		caps := e.toolCaps[t]
		desc := ""
		if d := b.agentToolDescription(e, t); d != "" {
			desc = " (" + d + ")"
		}
		basis := Evidence{Artifact: artInventory, Ref: e.Location, Statement: "tool " + t + " registered by agent " + name}
		if len(caps) == 0 {
			add("agent-tool", Question{
				ID: e.ID + "|" + t, Element: e.ID,
				Question: name + " registers tool " + t + desc + " and nox does not recognise its capability: what can it reach?",
				Basis:    basis,
			})
			continue
		}
		sorted := append([]string(nil), caps...)
		sort.Strings(sorted)
		add("agent-tool", Question{
			ID: e.ID + "|" + t, Element: e.ID,
			Question: name + " exposes " + strings.Join(sorted, ", ") + " to the model through tool " + t + desc + ": who may trigger it, and what confirms the request is allowed?",
			Basis:    basis,
		})
	}
}

func (b *builder) agentToolDescription(e *elem, tool string) string {
	if b.in.Inventory == nil {
		return ""
	}
	for _, set := range b.in.Inventory.ToolMatrix {
		if set.Server == "" && set.Path == e.Location && set.Agent == e.Attributes["agent"] {
			return set.Descriptions[tool]
		}
	}
	return ""
}

func (b *builder) routeQuestions(e *elem, add func(string, Question)) {
	if e.Attributes["authentication_middleware"] == "none visible" {
		add("route-auth", Question{
			ID: e.ID, Element: e.ID,
			Question: e.Name + " (" + e.Location + ") has no authentication middleware visible: is it meant to be callable without authentication?",
			Basis:    e.Evidence[0],
		})
	}
	for _, o := range e.obs {
		if o.cat == ElevationOfPrivilege && o.status == LeadsToVerify {
			add("route-lead", Question{
				ID: e.ID, Element: e.ID,
				Question: e.Name + " (" + o.ev.Ref + ") loads a record by a caller-supplied id with no visible ownership check: how does it make sure a caller reads only their own record? Test it with two accounts.",
				Basis:    o.ev,
			})
			break
		}
	}
}
