package intel

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox/core/evidence"
)

// CapabilityKind names an authority a component holds. Capabilities are what
// turn a vulnerability into a consequence: the same defect in a service that
// can only read a cache is not the same incident as one in a service that can
// execute a shell.
type CapabilityKind string

// Capability kinds. The set is open; values are slugs of the form
// "domain.action" so they read the same way in every report.
const (
	// CapabilityFilesystemRead — reads files from the host.
	CapabilityFilesystemRead CapabilityKind = "filesystem.read"
	// CapabilityFilesystemWrite — writes files to the host.
	CapabilityFilesystemWrite CapabilityKind = "filesystem.write"
	// CapabilityShellExecute — executes commands.
	CapabilityShellExecute CapabilityKind = "shell.execute"
	// CapabilitySecretRead — reads credentials or key material.
	CapabilitySecretRead CapabilityKind = "secret.read"
	// CapabilityNetworkEgress — initiates outbound network connections, which
	// is what turns read access into exfiltration.
	CapabilityNetworkEgress CapabilityKind = "network.egress"
	// CapabilityDatabaseRead — queries a datastore.
	CapabilityDatabaseRead CapabilityKind = "database.read"
	// CapabilityDatabaseWrite — mutates a datastore.
	CapabilityDatabaseWrite CapabilityKind = "database.write"
	// CapabilityIdentityAssume — assumes another identity or role, the usual
	// mechanism by which a small compromise becomes a large one.
	CapabilityIdentityAssume CapabilityKind = "identity.assume"
)

// Component is one deployed instance of an artifact in an organization's
// environment, with the facts that decide how far a vulnerability in it
// reaches.
type Component struct {
	// ID identifies the component within the organization.
	ID string `json:"id"`
	// Ecosystem, Package and Version identify the artifact it deploys.
	Ecosystem string `json:"ecosystem"`
	Package   string `json:"package"`
	Version   string `json:"version,omitempty"`
	// Service is the service the component belongs to.
	Service string `json:"service,omitempty"`
	// VulnerablePathReachable is true when static reachability established that
	// the vulnerable code path is actually linked and callable here. It mirrors
	// the dependency analyzer's reachability signal: a module that ships a
	// vulnerable package it never calls is present, not reachable.
	VulnerablePathReachable bool `json:"vulnerable_path_reachable"`
	// ExternallyExposed is true when an attacker-controlled entry point reaches
	// this component.
	ExternallyExposed bool `json:"externally_exposed"`
	// Capabilities are the authorities this component holds.
	Capabilities []CapabilityKind `json:"capabilities,omitempty"`
	// Identities are the roles or principals it can act as.
	Identities []string `json:"identities,omitempty"`
	// DataClasses are the classes of data it can reach.
	DataClasses []string `json:"data_classes,omitempty"`
}

// ReachItem is one element of a blast radius together with how far nox has
// actually established it reaches, and why.
//
// Every item carries its own Reach because the difference between "this service
// could in principle be touched" and "this service was demonstrably touched" is
// the difference between a backlog ticket and an incident. Flattening the two
// into one list — as a plain []string would — is how a theoretical blast radius
// gets read aloud in an incident call as a confirmed one.
type ReachItem struct {
	Name  string         `json:"name"`
	Reach evidence.Reach `json:"reach"`
	Why   string         `json:"why"`
}

// BlastRadius is what a vulnerability reaches in one organization, per
// dimension, each element labelled with its own established reach.
type BlastRadius struct {
	Services     []ReachItem `json:"services,omitempty"`
	Capabilities []ReachItem `json:"capabilities,omitempty"`
	Identities   []ReachItem `json:"identities,omitempty"`
	DataClasses  []ReachItem `json:"data_classes,omitempty"`
	// MaxReach is the highest rung any element reached. It is a summary of the
	// items, never a substitute for them.
	MaxReach evidence.Reach `json:"max_reach"`
}

// ComponentExposure is one component's position on the exposure ladder, with
// the reason it stopped there.
type ComponentExposure struct {
	ComponentID string         `json:"component_id"`
	Reach       evidence.Reach `json:"reach"`
	Why         string         `json:"why"`
}

// Containment is an action that would change the exposure, and how far it would
// change it.
type Containment struct {
	// Action is what to do.
	Action string `json:"action"`
	// Rationale explains the effect, and states that the projection is a
	// projection.
	Rationale string `json:"rationale"`
	// Kind is one of ContainmentRemediation, ContainmentContainment, or
	// ContainmentMitigation.
	Kind string `json:"kind"`
	// ProjectedReach is the reach nox expects to remain afterwards. It is
	// PROJECTED: nox has not observed the changed environment, and the field
	// name and rationale both say so, because a projected reach that reads like
	// a measured one is how a mitigation gets marked done without anyone
	// checking it worked.
	ProjectedReach evidence.Reach `json:"projected_reach"`
}

// Containment kinds. The distinction is not cosmetic: it tells an operator
// whether they have finished with the vulnerability or merely bought time.
const (
	// ContainmentRemediation removes the vulnerability itself.
	ContainmentRemediation = "remediation"
	// ContainmentContainment leaves the vulnerability in place and breaks the
	// attack path to it.
	ContainmentContainment = "containment"
	// ContainmentMitigation neither removes nor breaks: it lowers the
	// likelihood or the consequence, and the vulnerability remains.
	ContainmentMitigation = "mitigation"
)

// Exposure is what a candidate means in one organization's environment.
type Exposure struct {
	// CandidateID names the candidate assessed.
	CandidateID string `json:"candidate_id"`
	// Present, Reachable, Exposed, Exploitable and Confirmed count components
	// AT OR ABOVE each rung, so the numbers narrow as the ladder rises and can
	// be read as a funnel.
	Present     int `json:"present"`
	Reachable   int `json:"reachable"`
	Exposed     int `json:"exposed"`
	Exploitable int `json:"exploitable"`
	Confirmed   int `json:"confirmed"`
	// Components lists each affected component and where it stopped.
	Components []ComponentExposure `json:"components,omitempty"`
	// Reach is the highest rung established anywhere in this environment.
	Reach evidence.Reach `json:"reach"`
	// Blast is the per-dimension radius.
	Blast BlastRadius `json:"blast_radius"`
	// Containment lists the actions that would change the picture.
	Containment []Containment `json:"containment,omitempty"`
}

// Assess places a candidate on the exposure ladder for one environment.
//
// The ladder is PRESENT -> REACHABLE -> EXPOSED -> EXPLOITABLE -> VALIDATED ->
// CONFIRMED, and each rung requires its own evidence:
//
//   - PRESENT: the artifact is deployed here.
//   - REACHABLE: static reachability says the vulnerable path is callable.
//   - EXPOSED: an attacker-controlled entry point reaches that path.
//   - EXPLOITABLE: exposure plus HIGH-or-better confidence that the
//     vulnerability is real.
//   - VALIDATED / CONFIRMED: a dynamic run exercised the path here.
//
// Static evidence stops at EXPLOITABLE by construction. Nothing a scanner
// deduces from configuration can show that an attack works; only a run can, so
// the top two rungs are unreachable without an ExploitEvidence. A candidate
// with no dynamic evidence can therefore never be labelled CONFIRMED, which is
// the guarantee that keeps "theoretical" from being read as "happening".
//
// Dynamic evidence naming no ComponentID raises the environment's reach but no
// individual component's: the run proved something about the artifact, and
// spreading that proof across every deployment would claim observations nobody
// made. Dynamic evidence is ignored entirely when no component is affected —
// an exploit against an artifact the organization does not run is not exposure.
func Assess(c *Candidate, comps []Component, exploits []ExploitEvidence) Exposure {
	ex := Exposure{Reach: evidence.ReachTheoretical}
	if c == nil {
		return ex
	}
	ex.CandidateID = c.ID

	matched := matchingComponents(c, comps)
	if len(matched) == 0 {
		// Not present here. That is a real and useful answer: the candidate
		// exists, and this environment is not exposed to it.
		ex.Blast.MaxReach = evidence.ReachTheoretical
		return ex
	}

	perComponent, general := dynamicReach(c, exploits)
	staticCeiling := staticCeilingFor(c)

	blast := newBlastAccum()
	ex.Components = make([]ComponentExposure, 0, len(matched))
	for _, comp := range matched {
		reach, why := componentReach(comp, staticCeiling)
		if dyn, ok := perComponent[comp.ID]; ok && dyn.reach.AtLeast(reach) {
			reach, why = dyn.reach, dyn.why
		}
		ex.Components = append(ex.Components, ComponentExposure{
			ComponentID: comp.ID,
			Reach:       reach,
			Why:         why,
		})
		blast.absorb(comp, reach, why)
		ex.Reach = evidence.MaxReach(ex.Reach, reach)
	}
	if general.reach.AtLeast(ex.Reach) {
		ex.Reach = general.reach
	}

	ex.Present, ex.Reachable, ex.Exposed, ex.Exploitable, ex.Confirmed = rungCounts(ex.Components)
	ex.Blast = blast.build()
	ex.Containment = containments(c, matched, ex)
	return ex
}

// matchingComponents selects the components the candidate actually affects,
// sorted by ID for determinism.
//
// When the candidate's affected range is unparseable, a component that matches
// the artifact is kept. Dropping it would silently hide a real deployment,
// whereas keeping it only asserts PRESENT — and every rung above PRESENT still
// has to earn its own evidence.
func matchingComponents(c *Candidate, comps []Component) []Component {
	out := make([]Component, 0, len(comps))
	bounds := rangeBounds(c.AffectedRange)
	for _, comp := range comps {
		if !strings.EqualFold(normalizeEcosystem(comp.Ecosystem), c.Ecosystem) ||
			!strings.EqualFold(normalizePackage(comp.Package), c.Package) {
			continue
		}
		if !versionInSpan(normalizeVersion(comp.Version), bounds) {
			continue
		}
		out = append(out, comp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID < out[j].ID })
	return out
}

// versionInSpan reports whether v falls within the bounds extracted from a
// candidate's affected range. An unknown version or an unorderable bound
// yields true: see matchingComponents for why that direction is the safe one.
func versionInSpan(v string, bounds []string) bool {
	if v == "" || len(bounds) == 0 || !comparableVersion(v) {
		return true
	}
	lo, hi := "", ""
	for _, b := range bounds {
		if !comparableVersion(b) {
			return true
		}
		if lo == "" || compareVersions(b, lo) < 0 {
			lo = b
		}
		if hi == "" || compareVersions(b, hi) > 0 {
			hi = b
		}
	}
	return compareVersions(v, lo) >= 0 && compareVersions(v, hi) <= 0
}

// staticCeilingFor returns the highest rung static evidence may reach for this
// candidate. EXPLOITABLE requires HIGH-or-better confidence that the
// vulnerability is real; below that, an exposed component is exposed to
// something nox is not yet convinced exists.
func staticCeilingFor(c *Candidate) evidence.Reach {
	if c.Confidence().AtLeast(evidence.ConfidenceHigh) {
		return evidence.ReachExploitable
	}
	return evidence.ReachExposed
}

// componentReach walks one component up the static ladder and reports where it
// stopped and why.
func componentReach(comp Component, ceiling evidence.Reach) (evidence.Reach, string) {
	if !comp.VulnerablePathReachable {
		return evidence.ReachPresent,
			"the affected artifact is deployed here, but the vulnerable path was not shown to be reachable"
	}
	if !comp.ExternallyExposed {
		return evidence.ReachReachable,
			"the vulnerable path is reachable in this component, but no attacker-controlled entry point reaches it"
	}
	if !ceiling.AtLeast(evidence.ReachExploitable) {
		return evidence.ReachExposed,
			"an attacker-controlled entry point reaches the vulnerable path; the vulnerability itself is not yet corroborated enough to call it exploitable"
	}
	return evidence.ReachExploitable,
		"an attacker-controlled entry point reaches the vulnerable path, and the vulnerability is corroborated; exploitation has not been attempted here"
}

// dynamicClaim is a reach established by a run, with its citation.
type dynamicClaim struct {
	reach evidence.Reach
	why   string
}

// dynamicReach maps dynamic evidence onto the top two rungs.
//
// CONFIRMED requires a deterministic, reproduced violation — the same bar
// core/evidence sets for a confirmed exploitability state. A violation that was
// observed but did not reproduce, or was judged rather than measured, lands at
// VALIDATED: a run exercised the path, and that is all it showed. PREVENTED and
// INCONCLUSIVE raise nothing; "we did not exploit it" is not evidence about
// reach in either direction.
func dynamicReach(c *Candidate, exploits []ExploitEvidence) (perComponent map[string]dynamicClaim, general dynamicClaim) {
	perComponent = make(map[string]dynamicClaim)
	general = dynamicClaim{reach: evidence.ReachTheoretical}

	ordered := make([]ExploitEvidence, len(exploits))
	copy(ordered, exploits)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].TraceID < ordered[j].TraceID })

	for _, ev := range ordered {
		if !ev.Exploitability.Valid() {
			continue
		}
		if ev.Fingerprint != "" && c.Fingerprint != "" && ev.Fingerprint != c.Fingerprint {
			continue
		}
		var claim dynamicClaim
		switch {
		case ev.validates():
			claim = dynamicClaim{
				reach: evidence.ReachConfirmed,
				why:   fmt.Sprintf("a deterministic oracle observed the violation here and it reproduced (trace %s)", ev.TraceID),
			}
		case ev.Exploitability == evidence.Confirmed:
			claim = dynamicClaim{
				reach: evidence.ReachValidated,
				why:   fmt.Sprintf("a run exercised the path and observed a violation that was not established (trace %s)", ev.TraceID),
			}
		default:
			continue
		}
		if ev.ComponentID == "" {
			if claim.reach.AtLeast(general.reach) {
				general = claim
			}
			continue
		}
		if prev, ok := perComponent[ev.ComponentID]; !ok || claim.reach.AtLeast(prev.reach) {
			perComponent[ev.ComponentID] = claim
		}
	}
	return perComponent, general
}

// rungCounts counts components at or above each rung.
func rungCounts(comps []ComponentExposure) (present, reachable, exposed, exploitable, confirmed int) {
	for _, ce := range comps {
		if ce.Reach.AtLeast(evidence.ReachPresent) {
			present++
		}
		if ce.Reach.AtLeast(evidence.ReachReachable) {
			reachable++
		}
		if ce.Reach.AtLeast(evidence.ReachExposed) {
			exposed++
		}
		if ce.Reach.AtLeast(evidence.ReachExploitable) {
			exploitable++
		}
		if ce.Reach.AtLeast(evidence.ReachConfirmed) {
			confirmed++
		}
	}
	return present, reachable, exposed, exploitable, confirmed
}

// blastAccum collects blast-radius elements, keeping each one's highest
// established reach and the reason for it.
type blastAccum struct {
	services     map[string]ReachItem
	capabilities map[string]ReachItem
	identities   map[string]ReachItem
	dataClasses  map[string]ReachItem
}

func newBlastAccum() *blastAccum {
	return &blastAccum{
		services:     map[string]ReachItem{},
		capabilities: map[string]ReachItem{},
		identities:   map[string]ReachItem{},
		dataClasses:  map[string]ReachItem{},
	}
}

// absorb folds one component's dimensions in at the reach that component
// established.
func (b *blastAccum) absorb(comp Component, reach evidence.Reach, why string) {
	prefix := "via component " + comp.ID + ": "
	if comp.Service != "" {
		addItem(b.services, comp.Service, reach, prefix+why)
	}
	for _, kind := range comp.Capabilities {
		addItem(b.capabilities, string(kind), reach,
			prefix+"the component holds this capability; "+why)
	}
	for _, id := range comp.Identities {
		addItem(b.identities, id, reach,
			prefix+"the component can act as this identity; "+why)
	}
	for _, dc := range comp.DataClasses {
		addItem(b.dataClasses, dc, reach,
			prefix+"the component can reach this data class; "+why)
	}
}

// addItem keeps the strictly higher reach, so a later component with a weaker
// claim cannot overwrite a stronger one and the result is order-independent.
func addItem(into map[string]ReachItem, name string, reach evidence.Reach, why string) {
	if name == "" {
		return
	}
	if prev, ok := into[name]; ok && prev.Reach.AtLeast(reach) {
		return
	}
	into[name] = ReachItem{Name: name, Reach: reach, Why: why}
}

// build renders the accumulated dimensions in sorted order.
func (b *blastAccum) build() BlastRadius {
	br := BlastRadius{
		Services:     sortedItems(b.services),
		Capabilities: sortedItems(b.capabilities),
		Identities:   sortedItems(b.identities),
		DataClasses:  sortedItems(b.dataClasses),
	}
	br.MaxReach = evidence.ReachTheoretical
	for _, group := range [][]ReachItem{br.Services, br.Capabilities, br.Identities, br.DataClasses} {
		for _, item := range group {
			br.MaxReach = evidence.MaxReach(br.MaxReach, item.Reach)
		}
	}
	return br
}

// sortedItems returns the map's items ordered by name.
func sortedItems(in map[string]ReachItem) []ReachItem {
	if len(in) == 0 {
		return nil
	}
	out := make([]ReachItem, 0, len(in))
	for _, v := range in {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// containments proposes the actions that would change this exposure.
//
// The three kinds answer different questions and are never merged: remediation
// ends the vulnerability, containment leaves it in place and cuts the path to
// it, and mitigation only reduces likelihood or consequence. An operator who
// cannot tell which one they applied cannot tell whether they are finished.
func containments(c *Candidate, comps []Component, ex Exposure) []Containment {
	out := make([]Containment, 0, 3)

	out = append(out, Containment{
		Kind:   ContainmentRemediation,
		Action: fmt.Sprintf("upgrade %s %s out of the affected range %s", c.Ecosystem, c.Package, displayRange(c.AffectedRange)),
		Rationale: "Removes the vulnerable code from the environment; nothing further is required. " +
			"Projected, not verified: nox has not observed the upgraded build.",
		ProjectedReach: evidence.ReachTheoretical,
	})

	if services := exposedServices(comps); len(services) > 0 {
		out = append(out, Containment{
			Kind:   ContainmentContainment,
			Action: fmt.Sprintf("remove or authenticate the external entry point to %s", strings.Join(services, ", ")),
			Rationale: "Breaks the attacker-controlled path to the vulnerable code without changing the dependency; " +
				"the vulnerability remains present and reachable. Projected, not verified.",
			ProjectedReach: evidence.ReachReachable,
		})
	}

	if caps := reachableCapabilities(comps); len(caps) > 0 {
		out = append(out, Containment{
			Kind:   ContainmentMitigation,
			Action: fmt.Sprintf("withdraw %s from the affected components", strings.Join(caps, ", ")),
			Rationale: "Reduces what an attacker gains, not whether they get in; the vulnerable path stays reachable, " +
				"so the reach is unchanged. Projected, not verified.",
			ProjectedReach: ex.Reach,
		})
	}

	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Action < out[j].Action
	})
	return out
}

// displayRange renders an empty affected range readably rather than as a gap in
// a sentence.
func displayRange(r string) string {
	if r == "" {
		return "(unbounded)"
	}
	return r
}

// exposedServices lists the distinct services with an externally exposed,
// reachable component.
func exposedServices(comps []Component) []string {
	out := make([]string, 0, len(comps))
	for _, comp := range comps {
		if comp.ExternallyExposed && comp.VulnerablePathReachable && comp.Service != "" {
			out = append(out, comp.Service)
		}
	}
	return dedupeStrings(out)
}

// reachableCapabilities lists the distinct capabilities held by components
// whose vulnerable path is reachable.
func reachableCapabilities(comps []Component) []string {
	out := make([]string, 0, len(comps))
	for _, comp := range comps {
		if !comp.VulnerablePathReachable {
			continue
		}
		for _, kind := range comp.Capabilities {
			out = append(out, string(kind))
		}
	}
	return dedupeStrings(out)
}
