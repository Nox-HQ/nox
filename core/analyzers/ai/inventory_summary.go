package ai

import (
	"fmt"
	"sort"
	"strings"
)

// schemaVersion is the ai.inventory.json format. 2.1.0 added Checks.
const schemaVersion = "2.1.0"

// inventoryChecks names every AI check ScanArtifacts runs, in a fixed order so
// the inventory stays byte-identical run to run. Recording them is what lets a
// reader tell "nox looked and found nothing" from "nox did not look": a scan
// that skipped the AI scope carries an inventory with no checks.
var inventoryChecks = []string{
	"ai_security_rules",
	"agent_tool_lattice",
	"mcp_config",
	"prompt_and_agent_files",
	"model_references",
	"sdk_invocations",
	"prompt_templates",
	"tool_permissions",
	"agent_frameworks",
}

// summaryModelLimit caps how many models the one-line summary names.
const summaryModelLimit = 3

// DistinctModels returns one reference per distinct model (provider and name)
// across the workspace, sorted by name then provider. ModelProvenance keeps
// one row per file because that is where a model is called from; a model
// called from ten files is still one model the application depends on.
func (inv *Inventory) DistinctModels() []ModelReference {
	if inv == nil {
		return nil
	}
	seen := make(map[string]bool, len(inv.ModelProvenance))
	var out []ModelReference
	for _, ref := range inv.ModelProvenance {
		key := ref.Registry + "\x00" + ref.Name
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, ref)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Name != out[j].Name {
			return out[i].Name < out[j].Name
		}
		return out[i].Registry < out[j].Registry
	})
	return out
}

// ComponentCount is the number of AI components the workspace uses: the
// inventoried components (MCP servers, prompt files, agent frameworks, vector
// stores) plus each distinct model. Every output that reports a count reads
// this, so the console, the MCP server and the dashboard cannot disagree.
func (inv *Inventory) ComponentCount() int {
	if inv == nil {
		return 0
	}
	return len(inv.Components) + len(inv.DistinctModels())
}

// Summary renders the count for a human, naming the models, e.g.
// "1 AI component (1 model: gpt-4o via openai)".
func (inv *Inventory) Summary() string {
	n := inv.ComponentCount()
	noun := "AI components"
	if n == 1 {
		noun = "AI component"
	}
	s := fmt.Sprintf("%d %s", n, noun)
	models := inv.DistinctModels()
	if len(models) == 0 {
		return s
	}
	names := make([]string, 0, summaryModelLimit+1)
	for i, m := range models {
		if i == summaryModelLimit {
			names = append(names, fmt.Sprintf("+%d more", len(models)-summaryModelLimit))
			break
		}
		names = append(names, ModelLabel(m))
	}
	label := "models"
	if len(models) == 1 {
		label = "model"
	}
	return fmt.Sprintf("%s (%d %s: %s)", s, len(models), label, strings.Join(names, ", "))
}

// ModelLabel names a model with its provider when the provider is known.
func ModelLabel(m ModelReference) string {
	if m.Registry == "" || m.Registry == "unknown" {
		return m.Name
	}
	return m.Name + " via " + m.Registry
}

// normalized returns a copy safe to serialise: the zero-value inventory a
// skipped AI scope carries still says which format it is, and its lists are
// empty arrays rather than null.
func (inv *Inventory) normalized() Inventory {
	out := Inventory{}
	if inv != nil {
		out = *inv
	}
	if out.SchemaVersion == "" {
		out.SchemaVersion = schemaVersion
	}
	if out.Components == nil {
		out.Components = []Component{}
	}
	if out.Checks == nil {
		out.Checks = []string{}
	}
	return out
}
