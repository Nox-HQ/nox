package attack

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/report"
)

// authzRuleID is the object-level authorization rule. Its leads (the rule
// disabled) and its findings (the rule enabled) are the same proposition, so
// both ground the same hypothesis.
const authzRuleID = "AUTHZ-001"

// authzCategory is the Lead.Category object-level authorization leads carry.
const authzCategory = "authorization"

// authzPlanOnlyReason is why `nox attack run` does not execute AUTHZ-BOLA.
//
// The run harness posts a payload corpus at a model and scores the reply with
// canary and refusal oracles. A BOLA test is a differential between two
// authenticated principals over an object one of them owns. That needs two
// credentials, the identifier of an object user B owns, and an oracle that
// compares the two responses; none of it exists in the harness, and pointing
// the injection corpus at a route like GET /invoices/:id would find nothing
// and read as a defence.
const authzPlanOnlyReason = "nox attack run has no two-principal differential oracle: it needs two " +
	"credentials and the id of an object the second user owns, and its current oracles score " +
	"model replies, not ownership. Run the procedure by hand; until then this hypothesis stays " +
	"unexecuted, and a run reports it as not run rather than as prevented."

var authzBOLAScenario = Scenario{
	ID:        ScenarioAuthzBOLA,
	Category:  "broken_access_control",
	Objective: "read or modify another user's object by naming its identifier while authenticated as a different user",
	Techniques: []string{
		"identifier substitution (BOLA / IDOR)",
		"two-account differential",
	},
	Invariants: []Invariant{
		{ID: "inv-authz-bola-ownership", Statement: "an authenticated caller must only be able to reach objects they own or are granted", AssetID: "asset-other-users-data"},
	},
	Preconditions: []string{
		"the route requires an authenticated caller",
		"the route loads a record by an identifier the caller supplies",
		"two accounts exist, each owning at least one object",
	},
	SafetyConstraints: []string{
		"read-only methods first; never modify or delete the other account's object",
		"use test accounts and test data you own, never real customers' records",
		"credentials come from flags or the environment and are never written to a plan or trace",
	},
	MinProfile: ProfileStaging,
	// CWE-639 (authorization bypass through user-controlled key) and OWASP API
	// Top 10 2023 API1 are the tags the static AUTHZ-001 finding already
	// carries. The vector scores a demonstrated cross-account READ: network,
	// low privilege (the attacker is a legitimate user), confidentiality only.
	OWASPAPI:       "API1:2023",
	CWE:            "CWE-639",
	CVSSVector:     "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:H/VI:N/VA:N/SC:N/SI:N/SA:N",
	PlanOnly:       true,
	PlanOnlyReason: authzPlanOnlyReason,
}

// routeParamPattern matches the path-parameter spellings the route readers
// accept: Express/Fastify/NestJS ":id", OpenAPI/FastAPI "{id}", Flask/Django
// "<id>" or "<int:id>", Next.js "[id]".
var routeParamPattern = regexp.MustCompile(`:([A-Za-z_][A-Za-z0-9_]*)|\{([A-Za-z_][A-Za-z0-9_]*)\}|<(?:[A-Za-z_]+:)?([A-Za-z_][A-Za-z0-9_]*)>|\[(?:\.\.\.)?([A-Za-z_][A-Za-z0-9_]*)\]`)

// authzTarget is the input every BOLA hypothesis is built from, whether it came
// from a lead or from an AUTHZ-001 finding.
type authzTarget struct {
	method, path string
	file         string
	line         int
	idSource     string
	// fingerprint is set when a finding grounds the target; leads have none.
	fingerprint string
	// statement is what the scan observed.
	statement string
}

// authzTargets collects the BOLA candidates from leads and findings,
// deduplicated by route and location and sorted for a deterministic plan.
func authzTargets(leads []report.Lead, ff []findings.Finding) []authzTarget {
	seen := map[string]bool{}
	var out []authzTarget
	add := func(t authzTarget) {
		k := t.method + " " + t.path + "|" + t.file + fmt.Sprint(t.line)
		if t.method == "" || t.path == "" || seen[k] {
			return
		}
		seen[k] = true
		out = append(out, t)
	}
	for i := range ff {
		f := ff[i]
		if f.RuleID != authzRuleID {
			continue
		}
		method, path, _ := strings.Cut(f.Metadata["route"], " ")
		add(authzTarget{
			method: method, path: path, file: f.Location.FilePath, line: f.Location.StartLine,
			idSource: f.Metadata["id_source"], fingerprint: f.Fingerprint, statement: f.Message,
		})
	}
	for i := range leads {
		l := leads[i]
		if l.RuleID != authzRuleID || (l.Category != "" && l.Category != authzCategory) {
			continue
		}
		method, path, _ := strings.Cut(l.Route, " ")
		add(authzTarget{
			method: method, path: path, file: l.FilePath, line: l.Line,
			idSource: l.IDSource, statement: l.Statement,
		})
	}
	sort.Slice(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if a.file != b.file {
			return a.file < b.file
		}
		if a.line != b.line {
			return a.line < b.line
		}
		return a.method+" "+a.path < b.method+" "+b.path
	})
	return out
}

// objectParameter names the parameter that selects the object, and where it
// travels. The name is only known for a path parameter; for a query or body
// identifier the scan recorded the source but not the key, and inventing one
// would read as knowledge, so the name is left empty.
func objectParameter(t authzTarget) (name, location string) {
	sources := strings.Split(t.idSource, ",")
	if t.idSource == "" || contains(sources, "path") {
		matches := routeParamPattern.FindAllStringSubmatch(t.path, -1)
		if len(matches) > 0 {
			m := matches[len(matches)-1] // the innermost segment names the object
			for _, g := range m[1:] {
				if g != "" {
					return g, "path"
				}
			}
		}
	}
	for _, loc := range []string{"query", "body"} {
		if contains(sources, loc) {
			return "", loc
		}
	}
	return "", ""
}

func contains(ss []string, s string) bool {
	for _, x := range ss {
		if x == s {
			return true
		}
	}
	return false
}

// authzHypothesis builds one BOLA/IDOR hypothesis. It is grounded in a lead or
// finding that says a route loads a record by a caller-supplied id with no
// visible ownership check; the hypothesis is that the check is missing at runtime
// too, which only a two-account test can settle.
func authzHypothesis(t authzTarget) Hypothesis {
	scen := authzBOLAScenario
	param, loc := objectParameter(t)
	route := t.method + " " + t.path

	input := "the object identifier"
	switch {
	case param != "" && loc != "":
		input = fmt.Sprintf("%s (%s parameter)", param, loc)
	case loc != "":
		input = fmt.Sprintf("the object identifier in the request %s (parameter name not recorded)", loc)
	}

	rationale := fmt.Sprintf(
		"%s at %s:%d: %s. No ownership check is visible between the caller's identity and that lookup, "+
			"so %s tests whether user A can fetch user B's object by sending B's identifier.",
		route, t.file, t.line, strings.TrimSpace(t.statement), ScenarioAuthzBOLA)

	h := Hypothesis{
		ID:         "hyp-" + ScenarioAuthzBOLA + "-" + shortID(route, t.file, fmt.Sprint(t.line)),
		ScenarioID: ScenarioAuthzBOLA,
		Objective:  scen.Objective,
		Rationale:  rationale,
		EntryPoint: route,
		Path: []PathStep{
			{Kind: StepEntryPoint, ID: "entry", Label: "authenticated request as user A: " + route},
			{Kind: StepSink, ID: "lookup", Label: fmt.Sprintf("record lookup by caller-supplied id (%s:%d)", t.file, t.line)},
			{Kind: StepAsset, ID: "asset-other-users-data", Label: "user B's object"},
		},
		InvariantIDs:     []string{scen.Invariants[0].ID},
		AttackerInput:    input,
		TriggerCondition: "suspected: the handler returns the object named by the identifier without comparing its owner to the authenticated caller",
		ExpectedOracle:   "ownership_differential: user A's request for user B's object is refused (403/404), or returns something other than B's object",
		Assumptions: []string{
			"the route is reachable by an authenticated user other than the object's owner",
			"no ownership or tenancy check exists outside the handler nox read (middleware, a database policy, a view), because nox saw none",
			"the identifier is not an unguessable capability; if it is, exposure needs a second leak",
		},
		Unknowns: []string{
			"whether a database row-level policy or a scoped query helper enforces ownership out of sight of the route reader",
			"whether the identifier of another user's object is obtainable by an attacker",
		},
		TestProcedure: authzProcedure(t, param, loc),
	}
	if t.fingerprint != "" {
		h.FindingFingerprints = []string{t.fingerprint}
	}
	return h
}

// authzProcedure writes the two-account test. The secure and vulnerable
// outcomes are fixed before anything is sent, and a setup failure has its own
// inconclusive outcome so it cannot be read as a defence.
func authzProcedure(t authzTarget, param, loc string) *TestProcedure {
	route := t.method + " " + t.path
	where := "the object identifier"
	switch {
	case param != "" && loc == "path":
		where = fmt.Sprintf("the %q path segment", param)
	case param != "":
		where = fmt.Sprintf("the %q %s parameter", param, loc)
	case loc != "":
		where = fmt.Sprintf("the object identifier in the request %s", loc)
	}
	concrete := route
	if param != "" && loc == "path" {
		concrete = t.method + " " + routeParamPattern.ReplaceAllString(t.path, "<B_OBJECT_ID>")
	}
	return &TestProcedure{
		Method:                  t.method,
		Route:                   t.path,
		ObjectParameter:         param,
		ObjectParameterLocation: loc,
		Preconditions: []string{
			"a non-production target you are authorized to test, with test data only",
			"two accounts, user A and user B, with credentials for each",
			"user B owns an object (call its id B_OBJECT_ID) and user A does not",
			"the route works for the owner: step 1 below returns B's object",
		},
		Steps: []string{
			fmt.Sprintf("1. Control: as user B, send %s with %s set to B_OBJECT_ID. Record the status and body. This must be 200 with B's object; if not, stop (inconclusive).", concrete, where),
			fmt.Sprintf("2. Test: as user A, send the same request, %s with %s set to B_OBJECT_ID. Record the status and body.", route, where),
			"3. Compare: is the body from step 2 the same object as step 1 (same id and owner-specific fields)?",
			"4. Negative control: as user A, request one of A's own objects. It must succeed, so a refusal in step 2 is about ownership and not about A's session.",
		},
		SecureResponse:     "Step 2 is refused (403 Forbidden, or 404 Not Found when the API hides existence) or returns no data belonging to user B.",
		VulnerableResponse: "Step 2 returns 200 with user B's object: the same id and owner-specific fields as step 1. Capture both responses as the reproduction evidence.",
		Inconclusive:       "Step 1 or step 4 fails (bad credentials, wrong id, expired session), or step 2 returns 401 for both users. None of these shows ownership is enforced.",
		Executable:         false,
		ExecutionNote:      authzPlanOnlyReason,
	}
}

// authzGround returns the BOLA hypotheses for the plan's leads and AUTHZ-001
// findings, registering their asset, boundary and scenario, and recording the
// findings they ground.
func authzGround(in PlanInput, assets map[string]Asset, boundaries map[string]TrustBoundary,
	used map[string]bool, grounded map[string]bool) []Hypothesis {
	targets := authzTargets(in.Leads, in.Findings)
	if len(targets) == 0 {
		return nil
	}
	used[ScenarioAuthzBOLA] = true
	assets["asset-other-users-data"] = Asset{
		ID: "asset-other-users-data", Kind: AssetTenantBoundary,
		Label: "objects owned by other authenticated users",
	}
	boundaries["bnd-user-user"] = TrustBoundary{
		ID: "bnd-user-user", From: "authenticated user A", To: "user B's objects",
		Label: "an authenticated caller's request crosses into another user's data",
	}
	hyps := make([]Hypothesis, 0, len(targets))
	for _, t := range targets {
		h := authzHypothesis(t)
		if t.fingerprint != "" {
			grounded[t.fingerprint] = true
			for i := range in.Findings {
				if in.Findings[i].Fingerprint == t.fingerprint {
					attachEvidence(&h, in.Findings[i], in)
					break
				}
			}
		}
		hyps = append(hyps, h)
	}
	return hyps
}
