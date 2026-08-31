// Package findings defines the canonical security findings model used across
// all Nox analyzers and reporters. Every scanner produces Finding values
// which are collected into a FindingSet for deduplication, sorting, and
// downstream consumption by report formatters (SARIF, SBOM, etc.).
package findings

import (
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// Severity indicates how critical a finding is. The values are ordered from
// most to least severe and are compatible with SARIF level mappings.
type Severity string

// Severity level constants ordered from most to least severe.
const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// IsValid reports whether s is one of the defined severity levels.
func (s Severity) IsValid() bool {
	switch s {
	case SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo:
		return true
	}
	return false
}

// Downgraded returns the severity one level less severe (critical→high→
// medium→low→info). Info is the floor and returns itself, so repeated
// application is idempotent at the bottom. An unrecognized severity is
// returned unchanged so callers never fabricate an invalid level.
func (s Severity) Downgraded() Severity {
	switch s {
	case SeverityCritical:
		return SeverityHigh
	case SeverityHigh:
		return SeverityMedium
	case SeverityMedium:
		return SeverityLow
	case SeverityLow, SeverityInfo:
		return SeverityInfo
	default:
		return s
	}
}

// Upgraded returns the severity one level more severe (info->low->medium->high->
// critical). Critical is the ceiling and returns itself, so repeated application
// is idempotent at the top. An unrecognized severity is returned unchanged. It
// is the inverse of Downgraded, used by severity recalibration.
func (s Severity) Upgraded() Severity {
	switch s {
	case SeverityInfo:
		return SeverityLow
	case SeverityLow:
		return SeverityMedium
	case SeverityMedium:
		return SeverityHigh
	case SeverityHigh, SeverityCritical:
		return SeverityCritical
	default:
		return s
	}
}

// Status indicates the disposition of a finding relative to baselines and
// inline suppressions.
type Status string

// Finding status values used by the scan pipeline.
const (
	StatusNew                   Status = "new"
	StatusBaselined             Status = "baselined"
	StatusSuppressed            Status = "suppressed"
	StatusVEXNotAffected        Status = "vex_not_affected"
	StatusVEXUnderInvestigation Status = "vex_under_investigation"
	StatusVEXFixed              Status = "vex_fixed"
)

// IsActive returns true if the finding should be reported (not suppressed,
// baselined, or marked not affected/fixed via VEX).
func (s Status) IsActive() bool {
	switch s {
	case StatusSuppressed, StatusBaselined, StatusVEXNotAffected, StatusVEXFixed:
		return false
	}
	return true
}

// Confidence expresses how certain the scanner is that the finding is a true
// positive rather than a false positive.
type Confidence string

// Confidence level constants for finding certainty.
const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// IsValid reports whether c is one of the defined confidence levels.
func (c Confidence) IsValid() bool {
	switch c {
	case ConfidenceHigh, ConfidenceMedium, ConfidenceLow:
		return true
	}
	return false
}

// Location pinpoints where a finding was detected within a source file. The
// fields map directly to the SARIF physicalLocation / region model so that
// report generation can consume them without translation.
type Location struct {
	FilePath    string
	StartLine   int
	EndLine     int
	StartColumn int
	EndColumn   int
}

// Normalized returns a copy of the location with a sane EndLine: a zero or
// out-of-order EndLine is set to StartLine so consumers always see a valid
// range (StartLine <= EndLine).
func (l Location) Normalized() Location {
	if l.EndLine == 0 || l.EndLine < l.StartLine {
		l.EndLine = l.StartLine
	}
	return l
}

// Finding is a single security observation produced by an analyzer. It is the
// canonical unit of output for the entire Nox pipeline.
type Finding struct {
	ID          string
	RuleID      string
	Severity    Severity
	Confidence  Confidence
	Location    Location
	Message     string
	Fingerprint string
	Metadata    map[string]string
	Status      Status `json:"Status,omitempty"`

	// Exploitability is the adjudicated lifecycle state, present only on scans
	// that recorded reasoning (ScanOptions.RecordReasoning). It is a state
	// label, NOT a ledger: the evidence itself lives out-of-band, for the
	// reasons measured in docs/benchmarks/2026-Q3/ledger-budget.md.
	//
	// Empty means the scan did not adjudicate, which is different from
	// POTENTIAL — one says nothing was asked, the other says static evidence
	// exists and no attack path was constructed. Consumers must not read an
	// absent value as either a state or a clearance.
	Exploitability string `json:",omitempty"`

	// EvidenceConfidence is what the recorded evidence supports, on the
	// kernel's scale (LOW, MEDIUM, HIGH, CONFIRMED). Present only on scans that
	// recorded reasoning; empty means nothing was adjudicated.
	//
	// It sits BESIDE Confidence rather than replacing it, and the distinction
	// is the whole of Track C5. The two answer different questions:
	//
	//	Confidence         how likely is this finding a true positive
	//	EvidenceConfidence what strength of evidence was recorded for it
	//
	// Neither substitutes for the other. Confidence is a calibration claim
	// about the rule, and on the precision suite it is right — 37 true
	// positives, no false ones, so the analyzers' "high" is accurate.
	// EvidenceConfidence is a statement about the ledger's contents, and it
	// caps at MEDIUM for any static scan: the kernel puts HIGH at strength 70,
	// which is source_confirmed, controlled_reproduction or a public advisory,
	// and a pattern scanner reaches KindStatic at 40.
	//
	// That cap is why the plan's original C5 — retire Confidence and let the
	// adjudicator author it — was measured and abandoned. Under it, every
	// finding on both corpora fell to medium or low, `--min-confidence high`
	// went from 11 findings to zero, and it would have gone to zero on every
	// project forever, because no static scan can clear 70. A filter that
	// always returns nothing reads exactly like a clean repository.
	//
	// So the analyzer keeps authorship of Confidence, and the evidence gets its
	// own field to disagree in. Where they disagree is reported rather than
	// resolved — see ScanResult.Divergences.
	EvidenceConfidence string `json:",omitempty"`

	// RetiredRuleIDs are the IDs of retired rules that reported THIS finding's
	// condition at THIS location before they were retired, and AliasFingerprints
	// are the fingerprints those rules would have produced here.
	//
	// They exist so a waiver written before the retirement keeps working. A
	// baseline entry is keyed on a fingerprint that hashes the rule ID, and a
	// VEX statement or nox:ignore comment names the rule ID outright, so
	// retiring a duplicate ID would otherwise un-waive every finding accepted
	// under it — turning gates red across every consuming repo for a change
	// that fixed a double-report.
	//
	// Both are populated only where the retired rule's own pattern actually
	// matches, so an alias never reaches a location the retired rule never
	// reported. That is what keeps an ID-level waiver from widening: it still
	// covers exactly the conditions it used to cover.
	//
	// Nil for the overwhelming majority of findings; omitted from JSON when
	// empty, but serialized when present so the scan cache round-trips them
	// (a cache hit must not quietly drop a waiver).
	RetiredRuleIDs    []string `json:",omitempty"`
	AliasFingerprints []string `json:",omitempty"`
}

// MatchesRuleID reports whether id addresses this finding — either its current
// rule ID or one of the retired IDs it inherited (see RetiredRuleIDs). Use it
// wherever an operator names a rule in a waiver, so waivers written against a
// retired ID keep applying. Comparison is case-insensitive, matching the VEX
// path's existing behaviour.
func (f *Finding) MatchesRuleID(id string) bool {
	if id == "" {
		return false
	}
	if strings.EqualFold(f.RuleID, id) {
		return true
	}
	for _, retired := range f.RetiredRuleIDs {
		if strings.EqualFold(retired, id) {
			return true
		}
	}
	return false
}

// MatchesFingerprint reports whether fp addresses this finding, by full
// fingerprint or by an unambiguous prefix.
//
// Prefix matching exists because a full SHA-256 is 64 characters and nobody
// retypes one; every surface that lets a person name a finding accepts a
// prefix. It lives here rather than in each adapter because it had already
// drifted: the MCP server and the CLI each grew their own copy, differing on
// whether the input was lowercased, so the same prefix could resolve in one
// and not the other. That is the cross-adapter duplication this codebase has
// fixed five times before.
//
// An empty prefix matches nothing. Treating it as "matches everything" would
// turn a missing argument into a silent select-all, which is the wrong default
// on any surface that acts on what it selects.
func (f *Finding) MatchesFingerprint(fp string) bool {
	fp = strings.TrimSpace(fp)
	if fp == "" || f.Fingerprint == "" {
		return false
	}
	if strings.EqualFold(f.Fingerprint, fp) {
		return true
	}
	if strings.HasPrefix(strings.ToLower(f.Fingerprint), strings.ToLower(fp)) {
		return true
	}
	// A waiver written before a rule retirement names the fingerprint the
	// retired rule would have produced; the same courtesy applies to a person
	// naming one at a prompt.
	for _, alias := range f.AliasFingerprints {
		if strings.EqualFold(alias, fp) ||
			strings.HasPrefix(strings.ToLower(alias), strings.ToLower(fp)) {
			return true
		}
	}
	return false
}

// Addresses reports whether selector names this finding, by rule ID (current or
// retired) or by fingerprint (full or prefix). It is what every adapter should
// call when a person names a finding.
func (f *Finding) Addresses(selector string) bool {
	return f.MatchesRuleID(selector) || f.MatchesFingerprint(selector)
}

// NewFinding constructs a Finding with a normalized location. It is the
// preferred way to create findings: the location range is made valid and the
// caller's severity/confidence are used as-is (validate with Validate). Fields
// remain public for ergonomic construction; this factory centralizes the
// normalization that FindingSet.Add also applies.
func NewFinding(ruleID string, severity Severity, confidence Confidence, loc Location, message string) Finding {
	return Finding{
		RuleID:     ruleID,
		Severity:   severity,
		Confidence: confidence,
		Location:   loc.Normalized(),
		Message:    message,
	}
}

// Validate reports the first invariant a finding violates, or nil if it is
// well-formed: a rule ID, a valid severity and confidence, and a sane line
// range. Useful as a guard in tests and at analyzer boundaries.
func (f Finding) Validate() error {
	if f.RuleID == "" {
		return errors.New("finding: empty RuleID")
	}
	if !f.Severity.IsValid() {
		return fmt.Errorf("finding %s: invalid severity %q", f.RuleID, f.Severity)
	}
	if !f.Confidence.IsValid() {
		return fmt.Errorf("finding %s: invalid confidence %q", f.RuleID, f.Confidence)
	}
	if f.Location.StartLine < 0 || (f.Location.EndLine != 0 && f.Location.EndLine < f.Location.StartLine) {
		return fmt.Errorf("finding %s: invalid line range %d-%d", f.RuleID, f.Location.StartLine, f.Location.EndLine)
	}
	return nil
}

// FindingSet is an ordered, deduplicated collection of findings. It is the
// primary data structure passed between pipeline stages.
type FindingSet struct {
	items []Finding
}

// NewFindingSet returns an empty FindingSet ready for use.
func NewFindingSet() *FindingSet {
	return &FindingSet{}
}

// Add appends a finding to the set. If the finding has an empty Fingerprint,
// one is computed automatically from RuleID, Location, and Message so that
// every finding in the set is always fingerprintable. Empty ID is populated
// as "<RuleID>-<Fingerprint[:12]>" for stable cross-scan identity. Zero EndLine
// is defaulted to StartLine so that consumers always see a valid range.
//
//nolint:gocritic // Findings are passed by value throughout the pipeline for simplicity.
func (fs *FindingSet) Add(f Finding) {
	if f.Fingerprint == "" {
		f.Fingerprint = ComputeFingerprint(f.RuleID, f.Location, f.Message)
	}
	if f.ID == "" {
		fp := f.Fingerprint
		if len(fp) > 12 {
			fp = fp[:12]
		}
		f.ID = f.RuleID + "-" + fp
	}
	if f.Location.EndLine == 0 && f.Location.StartLine > 0 {
		f.Location.EndLine = f.Location.StartLine
	}
	fs.items = append(fs.items, f)
}

// Deduplicate removes findings that share the same Fingerprint, keeping only
// the first occurrence. Call this after all findings have been added and before
// producing output.
func (fs *FindingSet) Deduplicate() {
	seen := make(map[string]struct{}, len(fs.items))
	unique := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		finding := fs.items[i]
		// Key on fingerprint AND location, not fingerprint alone.
		//
		// The V2 fingerprint is deliberately line-independent so a baseline
		// survives code moving up or down a file. But an analyzer that builds
		// findings directly (weakcrypto, variants, slop) and leaves Add to
		// derive the fingerprint from a static Message produces the SAME
		// fingerprint for two genuinely distinct findings in one file — two
		// MD5 calls at lines 10 and 50. Keying dedup on fingerprint alone then
		// silently dropped the second, real finding. Two findings at different
		// positions are never duplicates; a true duplicate shares position too.
		key := fmt.Sprintf("%s|%d|%d", finding.Fingerprint, finding.Location.StartLine, finding.Location.StartColumn)
		if _, exists := seen[key]; exists {
			continue
		}
		seen[key] = struct{}{}
		unique = append(unique, finding)
	}
	fs.items = unique
}

// flowKey identifies one source→sink dataflow independently of which end of it
// a finding chose to anchor to.
type flowKey struct {
	ruleID     string
	path       string
	sourceLine string
	sinkLine   string
	sourceVar  string
}

// flowIdentity returns the dataflow a finding describes, and whether it
// describes one at all. A finding qualifies only if it names the tainted
// variable and the line its value came from; anything else is not a flow report
// and is never a candidate for flow collapsing.
//
// The sink line is read from metadata when present and otherwise taken from the
// finding's own location: an analyzer that does not say where the sink is is
// anchored at it. That convention is what lets a source-anchored finding and a
// sink-anchored one about the same flow produce the same key.
func flowIdentity(f *Finding) (flowKey, bool) {
	sourceLine, sourceVar := f.Metadata["source_line"], f.Metadata["source_var"]
	if sourceLine == "" || sourceVar == "" {
		return flowKey{}, false
	}
	sinkLine := f.Metadata["sink_line"]
	if sinkLine == "" {
		sinkLine = strconv.Itoa(f.Location.StartLine)
	}
	return flowKey{
		ruleID:     f.RuleID,
		path:       normaliseFilePath(f.Location.FilePath),
		sourceLine: sourceLine,
		sinkLine:   sinkLine,
		sourceVar:  sourceVar,
	}, true
}

// FlowID returns a stable identity for the dataflow a finding describes, and
// whether it describes one at all.
//
// It is the same identity DeduplicateFlows merges on, exported so a caller can
// name the flow as a SUBJECT rather than only use it to collapse duplicates.
// That distinction is the whole of Track F: two findings that dedup collapses
// are not two vulnerabilities, they are one condition observed twice — and
// until the condition itself could be named, there was nowhere to say so.
//
// Deliberately NOT keyed on the rule ID, unlike flowKey. Two different rules
// reporting the same source reaching the same sink are reporting one flow;
// including the rule would give them different identities and reintroduce, at
// the subject level, exactly the double-counting this is meant to expose.
func FlowID(f *Finding) (string, bool) {
	sourceLine, sourceVar := f.Metadata["source_line"], f.Metadata["source_var"]
	if sourceLine == "" || sourceVar == "" {
		return "", false
	}
	sinkLine := f.Metadata["sink_line"]
	if sinkLine == "" {
		sinkLine = strconv.Itoa(f.Location.StartLine)
	}
	return fmt.Sprintf("%s:%s->%s:%s", normaliseFilePath(f.Location.FilePath),
		sourceLine, sinkLine, sourceVar), true
}

// anchoredAtSink reports whether a flow finding sits on its sink line.
func anchoredAtSink(f *Finding) bool {
	sinkLine := f.Metadata["sink_line"]
	return sinkLine == "" || sinkLine == strconv.Itoa(f.Location.StartLine)
}

// preferFlowFinding reports whether a should be kept over b when both describe
// the same flow. The sink anchor wins — that is where the fix goes, and it is
// the anchor already recorded in existing baselines. The remaining tiebreaks
// (line, then fingerprint) exist only to make the choice independent of the
// order analyzers happened to run in.
func preferFlowFinding(a, b *Finding) bool {
	if as, bs := anchoredAtSink(a), anchoredAtSink(b); as != bs {
		return as
	}
	if a.Location.StartLine != b.Location.StartLine {
		return a.Location.StartLine < b.Location.StartLine
	}
	return a.Fingerprint < b.Fingerprint
}

// DeduplicateFlows collapses findings that describe the SAME source→sink
// dataflow but disagree about which end of it to report.
//
// Deduplicate cannot do this. Its key is the fingerprint, which hashes the
// finding's message, plus the location — and two analyzers describing one flow
// word it differently and anchor it differently, so they collide on neither.
// The concrete case is Nox's built-in taint model and the nox/taint-analysis
// plugin: for one tainted variable reaching one sink, the built-in reports the
// sink line and the plugin reports the source line, under the same rule ID. One
// vulnerability then costs two alerts and two baseline entries, and no baseline
// can suppress both because the fingerprints differ.
//
// Identity is (rule, normalised path, source line, sink line, source variable),
// taken from the flow metadata analyzers already emit. Nothing weaker would be
// safe and nothing stronger is needed: two findings agreeing on all five are
// the same flow by any definition, and requiring more — the source kind, say —
// would let two engines that classify one HTTP source differently keep
// double-reporting it.
//
// Only a finding carrying that metadata participates, so this cannot touch a
// finding that is not a flow report, and a flow no other analyzer found is
// always kept. The collapse also only ever discards the source-anchored member
// of a pair, so a plugin cannot use it to displace a core finding.
func (fs *FindingSet) DeduplicateFlows() {
	best := make(map[flowKey]int, len(fs.items))
	drop := make(map[int]struct{})
	for i := range fs.items {
		key, ok := flowIdentity(&fs.items[i])
		if !ok {
			continue
		}
		prev, seen := best[key]
		if !seen {
			best[key] = i
			continue
		}
		keep, discard := prev, i
		if preferFlowFinding(&fs.items[i], &fs.items[prev]) {
			keep, discard = i, prev
		}
		best[key] = keep
		drop[discard] = struct{}{}
	}
	if len(drop) == 0 {
		return
	}
	kept := make([]Finding, 0, len(fs.items)-len(drop))
	for i := range fs.items {
		if _, dropped := drop[i]; dropped {
			continue
		}
		kept = append(kept, fs.items[i])
	}
	fs.items = kept
}

// SuppressDuplicateVulnClass drops a finding from suppressRulePrefix when
// another finding at the same file+line reports the same underlying vuln class
// via its "vuln_class" metadata. It resolves cross-analyzer over-reporting:
// when two SAST analyzers independently flag the same vulnerability at one
// location (e.g. the taint engine's TAINT-003 SSTI sink and the variants
// engine's VARIANT-005 SSTI CVE signature both firing on one
// render_template_string call), the more specific signature is kept and the
// generic taint duplicate is dropped, so the vulnerability is reported once.
//
// Suppression is class-scoped: a finding is only dropped when a *co-located,
// same-class* finding from a different rule exists. It never touches a lone
// finding and never crosses vuln classes, so it cannot hide a distinct
// vulnerability (an XSS finding is only ever suppressed by another XSS finding
// at the same span, which is itself reported). Deterministic and order-free.
func (fs *FindingSet) SuppressDuplicateVulnClass(suppressRulePrefix string) {
	// Index the vuln classes reported at each location by rules *other than* the
	// suppressible ones, so a suppressible finding can be dropped only when an
	// independent analyzer already covers the same class at the same span.
	type locKey struct {
		file string
		line int
	}
	covered := make(map[locKey]map[string]struct{})
	for i := range fs.items {
		f := &fs.items[i]
		if strings.HasPrefix(f.RuleID, suppressRulePrefix) {
			continue
		}
		class := f.Metadata["vuln_class"]
		if class == "" {
			continue
		}
		k := locKey{f.Location.FilePath, f.Location.StartLine}
		if covered[k] == nil {
			covered[k] = make(map[string]struct{})
		}
		covered[k][class] = struct{}{}
	}

	kept := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		f := fs.items[i]
		if strings.HasPrefix(f.RuleID, suppressRulePrefix) {
			if class := f.Metadata["vuln_class"]; class != "" {
				k := locKey{f.Location.FilePath, f.Location.StartLine}
				if classes, ok := covered[k]; ok {
					if _, dup := classes[class]; dup {
						continue // another analyzer already reports this class here
					}
				}
			}
		}
		kept = append(kept, f)
	}
	fs.items = kept
}

// SortDeterministic orders findings by RuleID, then FilePath, then StartLine,
// then Fingerprint. This guarantees stable, reproducible output regardless of
// the order in which analyzers emit their results.
//
// Fingerprint is the tiebreak and is not optional. RuleID/FilePath/StartLine is
// not a total order: every dependency vulnerability in one lockfile shares a
// rule, a path, and line 1, so a lockfile with 114 VULN-001 findings had 114
// findings tied on all three. Their relative order then came from whatever
// order the analyzer happened to emit them in — which, for dependency
// scanning, is Go map iteration, deliberately randomised. Two scans of
// identical inputs produced identically-sized but differently-ordered
// findings.json.
//
// That breaks nox's first stated constraint, that same inputs produce same
// outputs, and it breaks every consumer that compares two scans rather than
// reading one: nox diff, baseline drift, and any before/after comparison see
// pure reordering as change.
//
// Fingerprint is content-derived and assigned in Add, so it is populated for
// every finding by the time any sort runs, and it is unique per finding — which
// is what makes the ordering total rather than merely longer. preferFlowFinding
// already breaks its ties this way, for the same reason.
func (fs *FindingSet) SortDeterministic() {
	sort.Slice(fs.items, func(i, j int) bool {
		a, b := fs.items[i], fs.items[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Location.FilePath != b.Location.FilePath {
			return a.Location.FilePath < b.Location.FilePath
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.Fingerprint < b.Fingerprint
	})
}

// SeverityOrder lists the severities from most to least urgent. It is the one
// canonical ordering: severity breakdown lines, the priority rank below, and the
// SARIF/badge/policy orderings should all derive from this rather than
// re-declaring the sequence — a re-declared order is one that drifts.
var SeverityOrder = []Severity{
	SeverityCritical, SeverityHigh, SeverityMedium, SeverityLow, SeverityInfo,
}

// severityPriorityRank orders severities from most to least urgent, derived
// from SeverityOrder so the two cannot disagree.
var severityPriorityRank = func() map[Severity]int {
	m := make(map[Severity]int, len(SeverityOrder))
	for i, s := range SeverityOrder {
		m[s] = i
	}
	return m
}()

// SeverityRank returns a severity's position in SeverityOrder (0 = critical,
// most severe; 4 = info). An unrecognised severity ranks just past info, so it
// sorts last rather than tying with a real level. This is the one ranking the
// policy gate, the HTML report, and any severity sort must use, rather than
// each restating critical=0..info=4.
func SeverityRank(s Severity) int {
	if r, ok := severityPriorityRank[s]; ok {
		return r
	}
	return len(SeverityOrder)
}

// CountBySeverity tallies findings by severity. It is the companion to
// FormatSeverityCounts — every caller that wants a breakdown map used to roll
// its own identical loop.
func CountBySeverity(ff []Finding) map[Severity]int {
	counts := make(map[Severity]int, len(SeverityOrder))
	for i := range ff {
		counts[ff[i].Severity]++
	}
	return counts
}

// FormatSeverityCounts renders a severity->count map as "2 critical, 11 high,
// ..." in SeverityOrder, omitting zero counts. It returns "" for an all-zero or
// empty map; a caller that wants a word like "none" for the empty case supplies
// it. This is the one formatter behind every adapter's severity line.
func FormatSeverityCounts(counts map[Severity]int) string {
	var parts []string
	for _, s := range SeverityOrder {
		if n := counts[s]; n > 0 {
			parts = append(parts, fmt.Sprintf("%d %s", n, s))
		}
	}
	return strings.Join(parts, ", ")
}

// confidencePriorityRank orders confidence from most to least certain.
var confidencePriorityRank = map[Confidence]int{
	ConfidenceHigh: 0, ConfidenceMedium: 1, ConfidenceLow: 2,
}

// reachabilityRank ranks a finding by the reachability plugin's `reachable`
// enrichment: a confirmed-reachable finding is the most actionable, an
// unreachable one is a likely false positive and sinks. Findings never analyzed
// for reachability (no metadata) rank in the neutral middle, so enabling the
// reachability plugin only ever demotes likely-FPs — it never buries a normal
// finding beneath one.
//
// The plugin is now the ONLY producer of this key. The dependency analyzer used
// to write it too, from `go list -deps`, which establishes that an affected
// import is in the linked set — reach.SymbolReferenced, a strictly weaker
// proposition than the call-graph reachability this ranking is about. Two
// producers writing one key with different meanings put a linker answer and a
// call-graph answer in the same sort bucket. Dependency findings now carry
// `reach_level` and rank neutral here, which is the honest position for a
// question nothing in core answers.
func reachabilityRank(f *Finding) int {
	switch f.Metadata["reachable"] {
	case "true":
		return 0
	case "false":
		return 2
	default: // "undetermined" or absent
		return 1
	}
}

// SortByPriority orders findings for a human reading top-down: active findings
// before suppressed/baselined ones, then by severity, then by reachability
// (confirmed-reachable up, likely-false-positive unreachable down — see the
// reachability plugin), then confidence, then a stable location tiebreak. Use
// it for display/reporting; SortDeterministic remains the canonical order for
// baselines and diffs.
func (fs *FindingSet) SortByPriority() {
	sort.SliceStable(fs.items, func(i, j int) bool {
		a, b := fs.items[i], fs.items[j]
		if av, bv := a.Status.IsActive(), b.Status.IsActive(); av != bv {
			return av // active first
		}
		if ar, br := severityPriorityRank[a.Severity], severityPriorityRank[b.Severity]; ar != br {
			return ar < br
		}
		if ar, br := reachabilityRank(&a), reachabilityRank(&b); ar != br {
			return ar < br
		}
		if ac, bc := confidencePriorityRank[a.Confidence], confidencePriorityRank[b.Confidence]; ac != bc {
			return ac < bc
		}
		if a.Location.FilePath != b.Location.FilePath {
			return a.Location.FilePath < b.Location.FilePath
		}
		if a.Location.StartLine != b.Location.StartLine {
			return a.Location.StartLine < b.Location.StartLine
		}
		return a.RuleID < b.RuleID
	})
}

// RemoveByRuleIDs removes all findings whose RuleID matches any of the given
// IDs. A retired ID a finding inherited counts as a match (see RetiredRuleIDs):
// `rules.disable: [IAC-310]` in a config written before IAC-310 was retired is
// still an instruction to drop that condition, and honouring it is what stops a
// rule merge from re-enabling a rule the operator switched off.
func (fs *FindingSet) RemoveByRuleIDs(ids []string) {
	if len(ids) == 0 {
		return
	}
	kept := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		finding := fs.items[i]
		skip := false
		for _, id := range ids {
			if finding.MatchesRuleID(id) {
				skip = true
				break
			}
		}
		if !skip {
			kept = append(kept, finding)
		}
	}
	fs.items = kept
}

// OverrideSeverity changes the severity for all findings with the given rule ID.
func (fs *FindingSet) OverrideSeverity(ruleID string, severity Severity) {
	for i := range fs.items {
		if fs.items[i].RuleID == ruleID {
			fs.items[i].Severity = severity
		}
	}
}

// SetStatus sets the status of the finding at the given index.
func (fs *FindingSet) SetStatus(i int, s Status) {
	if i >= 0 && i < len(fs.items) {
		fs.items[i].Status = s
	}
}

// SetExploitability records the adjudicated lifecycle state of the finding at
// the given index. It mirrors SetStatus: the adjudicator holds a FindingSet,
// not the findings, and Findings() hands back a slice callers must not modify.
func (fs *FindingSet) SetExploitability(i int, state string) {
	if i >= 0 && i < len(fs.items) {
		fs.items[i].Exploitability = state
	}
}

// SetEvidenceConfidence records what the ledger supports about finding i.
//
// Deliberately separate from Confidence, which the analyzer authors and this
// must never touch: the two are different quantities, and C5 measured what
// happens when one is made to stand for the other. See the field's own
// documentation.
func (fs *FindingSet) SetEvidenceConfidence(i int, level string) {
	if i >= 0 && i < len(fs.items) {
		fs.items[i].EvidenceConfidence = level
	}
}

// CountByStatus returns a count of findings grouped by status.
// Findings with an empty status are counted under StatusNew.
func (fs *FindingSet) CountByStatus() map[Status]int {
	counts := make(map[Status]int)
	for i := range fs.items {
		finding := fs.items[i]
		s := finding.Status
		if s == "" {
			s = StatusNew
		}
		counts[s]++
	}
	return counts
}

// ActiveFindings returns findings that are not suppressed, baselined, or VEX-excluded.
func (fs *FindingSet) ActiveFindings() []Finding {
	var active []Finding
	for i := range fs.items {
		finding := fs.items[i]
		if !finding.Status.IsActive() {
			continue
		}
		active = append(active, finding)
	}
	return active
}

// Findings returns the current slice of findings. The caller must not modify
// the returned slice.
func (fs *FindingSet) Findings() []Finding {
	return fs.items
}

// RemoveByRuleIDsAndPaths removes findings that match both the given rule IDs
// AND any of the given path patterns. This enables granular exclusion based on
// rule + path combinations (e.g., disable VULN rules only for node_modules).
func (fs *FindingSet) RemoveByRuleIDsAndPaths(ruleIDs, paths []string) {
	if len(ruleIDs) == 0 && len(paths) == 0 {
		return
	}
	kept := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		finding := fs.items[i]
		skipRule := false
		if len(ruleIDs) > 0 {
			// ruleIDs may be exact IDs or wildcards (e.g. "VULN-*"), matching
			// the documented analyzer_rules behaviour.
			skipRule = matchRulePatterns(finding.RuleID, ruleIDs)
		}
		skipPath := false
		if len(paths) > 0 {
			skipPath = matchAnyPattern(finding.Location.FilePath, paths)
		}
		// Keep if EITHER rule or path doesn't match the exclusion criteria.
		// Skip only if BOTH rule and path match (both are true).
		if !skipRule || !skipPath {
			kept = append(kept, finding)
		}
	}
	fs.items = kept
}

// RemoveByRuleIDsInDirs removes findings whose RuleID matches any of ruleIDs
// (exact or wildcard) AND whose path contains any of the given directory-name
// segments. Used to drop content-rule findings inside test / fixture / example
// trees, which produce only false positives there.
func (fs *FindingSet) RemoveByRuleIDsInDirs(ruleIDs, dirSegments []string) {
	if len(ruleIDs) == 0 || len(dirSegments) == 0 {
		return
	}
	segSet := make(map[string]struct{}, len(dirSegments))
	for _, s := range dirSegments {
		segSet[strings.ToLower(s)] = struct{}{}
	}
	kept := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		f := fs.items[i]
		if matchRulePatterns(f.RuleID, ruleIDs) && pathHasSegment(f.Location.FilePath, segSet) {
			continue
		}
		kept = append(kept, f)
	}
	fs.items = kept
}

// pathHasSegment reports whether any slash-separated segment of path is in set.
func pathHasSegment(path string, set map[string]struct{}) bool {
	for _, seg := range strings.Split(filepath.ToSlash(path), "/") {
		if _, ok := set[strings.ToLower(seg)]; ok {
			return true
		}
	}
	return false
}

func matchAnyPattern(path string, patterns []string) bool {
	for _, pattern := range patterns {
		if matched, _ := filepath.Match(pattern, path); matched {
			return true
		}
		if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
			return true
		}
		if strings.HasPrefix(pattern, "*") {
			rest := strings.TrimPrefix(pattern, "*")
			if strings.HasSuffix(path, rest) || strings.HasSuffix(filepath.Base(path), rest) {
				return true
			}
		}
		if matchPathPattern(path, pattern) {
			return true
		}
	}
	return false
}

func matchPathPattern(path, pattern string) bool {
	pathParts := strings.Split(path, "/")
	patternParts := strings.Split(pattern, "/")

	if len(patternParts) > len(pathParts) {
		return false
	}

	for i, part := range patternParts {
		if part == "*" || part == "**" {
			continue
		}
		if i >= len(pathParts) {
			return false
		}
		if matched, _ := filepath.Match(part, pathParts[i]); !matched {
			return false
		}
	}
	return true
}

// OverrideSeverityByRuleIDAndPath changes the severity of findings that match
// both the given rule ID and path pattern.
func (fs *FindingSet) OverrideSeverityByRuleIDAndPath(ruleID, pathPattern string, severity Severity) {
	for i := range fs.items {
		finding := &fs.items[i]
		if finding.RuleID == ruleID && matchAnyPattern(finding.Location.FilePath, []string{pathPattern}) {
			finding.Severity = severity
		}
	}
}

// OverrideSeverityByRulePatternsAndPaths changes the severity of findings that match
// any of the given rule patterns (with wildcard support) AND any of the given path patterns.
// This enables conditional severity overrides (e.g., downgrade all VULN-* findings in node_modules to info).
func (fs *FindingSet) OverrideSeverityByRulePatternsAndPaths(rulePatterns, pathPatterns []string, severity Severity) {
	for i := range fs.items {
		finding := &fs.items[i]
		if matchRulePatterns(finding.RuleID, rulePatterns) && matchAnyPattern(finding.Location.FilePath, pathPatterns) {
			finding.Severity = severity
		}
	}
}

// DowngradeByRulePatternsAndPath lowers by one severity level (critical→high→
// medium→low→info) every finding whose RuleID matches any of rulePatterns AND
// whose FilePath satisfies pathMatch. For each finding it downgrades it records
// the pre-downgrade severity in Metadata["original_severity"] and sets
// Metadata["context"]=contextLabel so the change is auditable in reports and
// diffs. It returns the number of findings downgraded.
//
// The path predicate is injected rather than hard-coded so the caller owns the
// (context-specific, case-insensitive, **-spanning) glob semantics; this method
// stays a pure severity-and-metadata transform.
//
// A finding already sitting at info stays at info (Downgraded is a no-op there),
// but its audit metadata is still stamped so an operator can see the context
// classification even when no numeric change occurred. Findings whose
// original_severity is already recorded are skipped, keeping the operation
// idempotent across repeated refinement passes.
func (fs *FindingSet) DowngradeByRulePatternsAndPath(rulePatterns []string, pathMatch func(string) bool, contextLabel string) int {
	if len(rulePatterns) == 0 || pathMatch == nil {
		return 0
	}
	var count int
	for i := range fs.items {
		finding := &fs.items[i]
		if _, already := finding.Metadata["original_severity"]; already {
			continue
		}
		if !matchRulePatterns(finding.RuleID, rulePatterns) {
			continue
		}
		if !pathMatch(finding.Location.FilePath) {
			continue
		}
		if finding.Metadata == nil {
			finding.Metadata = make(map[string]string, 2)
		}
		finding.Metadata["original_severity"] = string(finding.Severity)
		finding.Metadata["context"] = contextLabel
		finding.Severity = finding.Severity.Downgraded()
		count++
	}
	return count
}

func matchRulePatterns(ruleID string, patterns []string) bool {
	for _, pattern := range patterns {
		if ruleID == pattern {
			return true
		}
		if strings.HasPrefix(pattern, "*") && strings.HasSuffix(pattern, "*") {
			mid := strings.TrimSuffix(strings.TrimPrefix(pattern, "*"), "*")
			if strings.Contains(ruleID, mid) {
				return true
			}
		}
		if strings.HasSuffix(pattern, "*") {
			prefix := strings.TrimSuffix(pattern, "*")
			if strings.HasPrefix(ruleID, prefix) {
				return true
			}
		}
	}
	return false
}

// SetMetadata records a key on finding i, creating the map if needed.
//
// Used by scan-stage annotations that are derived rather than authored by an
// analyzer — see recordAnalysisLimitations. Metadata is a non-ingredient field,
// so nothing written here can move a fingerprint; that is held by
// TestFingerprintIngredientsAreClosed.
func (fs *FindingSet) SetMetadata(i int, key, value string) {
	if i < 0 || i >= len(fs.items) || key == "" {
		return
	}
	if fs.items[i].Metadata == nil {
		fs.items[i].Metadata = map[string]string{}
	}
	fs.items[i].Metadata[key] = value
}
