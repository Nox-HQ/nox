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

// SortDeterministic orders findings by RuleID, then FilePath, then StartLine.
// This guarantees stable, reproducible output regardless of the order in which
// analyzers emit their results.
func (fs *FindingSet) SortDeterministic() {
	sort.Slice(fs.items, func(i, j int) bool {
		a, b := fs.items[i], fs.items[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Location.FilePath != b.Location.FilePath {
			return a.Location.FilePath < b.Location.FilePath
		}
		return a.Location.StartLine < b.Location.StartLine
	})
}

// severityPriorityRank orders severities from most to least urgent.
var severityPriorityRank = map[Severity]int{
	SeverityCritical: 0, SeverityHigh: 1, SeverityMedium: 2, SeverityLow: 3, SeverityInfo: 4,
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

// RemoveByRuleIDs removes all findings whose RuleID matches any of the given IDs.
func (fs *FindingSet) RemoveByRuleIDs(ids []string) {
	if len(ids) == 0 {
		return
	}
	disabled := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		disabled[id] = struct{}{}
	}
	kept := make([]Finding, 0, len(fs.items))
	for i := range fs.items {
		finding := fs.items[i]
		if _, skip := disabled[finding.RuleID]; !skip {
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

// nox:ignore SEC-659 -- false positive: strings.Split is not an API key
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

// nox:ignore SEC-659 -- false positive: function name triggers Split API Key detector

// OverrideSeverityByRulePatternsAndPaths changes the severity of findings that match
// any of the given rule patterns (with wildcard support) AND any of the given path patterns.
// This enables conditional severity overrides (e.g., downgrade all VULN-* findings in node_modules to info).
func (fs *FindingSet) OverrideSeverityByRulePatternsAndPaths(rulePatterns, pathPatterns []string, severity Severity) { // nox:ignore SEC-659
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
