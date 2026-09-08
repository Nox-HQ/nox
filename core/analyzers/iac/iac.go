// Package iac implements Infrastructure-as-Code security scanning. It wraps
// the core/rules engine with built-in rules that detect common IaC
// misconfigurations in Dockerfiles, Terraform files, and Kubernetes manifests.
package iac

import (
	"context"
	"fmt"
	"os"
	"strings"

	"path/filepath"

	"github.com/nox-hq/nox-core/evidence"

	"github.com/nox-hq/nox/core/discovery"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/reasoning"
	"github.com/nox-hq/nox/core/rules"
	"github.com/nox-hq/nox/core/rules/structural"
)

// Analyzer wraps a rules.Engine pre-loaded with IaC security rules.
type Analyzer struct {
	engine *rules.Engine
	// absence holds only the absence-matcher rules, and is run separately over
	// Kubernetes manifests embedded in YAML block scalars. Pattern rules match
	// inside a block scalar already, so they are deliberately excluded: running
	// them twice would double-report. See extractEmbeddedManifests.
	absence *rules.Engine
	// reasoning receives a claim for every finding this analyzer decided by
	// parsing the document rather than by matching text. Nil unless a caller
	// asked for evidence, which keeps recording free when nobody did.
	reasoning *reasoning.Store
}

// NewAnalyzer creates an Analyzer with built-in IaC security rules loaded
// programmatically. Rules are scoped to specific file types via FilePatterns.
func NewAnalyzer() *Analyzer {
	rs := rules.NewRuleSet()
	iacRules := builtinIaCRules()
	for i := range iacRules {
		rs.Add(&iacRules[i])
	}
	a := &Analyzer{engine: rules.NewEngine(rs)}
	// A second engine holding only the absence rules, for manifests embedded
	// in YAML block scalars. See extractEmbeddedManifests for why the pattern
	// rules must not be re-run over them.
	if ars := absenceRuleSet(iacRules); ars != nil {
		a.absence = rules.NewEngine(ars)
	}
	return a
}

// Rules returns the analyzer's RuleSet for catalog aggregation.
func (a *Analyzer) Rules() *rules.RuleSet { return a.engine.Rules() }

// RecordReasoningTo directs this analyzer's claims at store.
//
// The IaC family had no evidence seam at all until the structural path existed,
// and that was the honest state of things: every IAC finding rested on a
// pattern match, so the only claim it could have filed is the bare observation
// the scan already records. There was nothing to say. There is now.
func (a *Analyzer) RecordReasoningTo(store *reasoning.Store) { a.reasoning = store }

// recordStructuralClaims files what parsing established about each finding.
//
// The claim is KindStatic, and that is the point of the whole feature: "the
// resource was parsed and sets no BucketEncryption" is static analysis, while
// "no pattern matched inside a span I guessed by indentation" is a heuristic
// however carefully the pattern was written. It is the first claim in this
// family that can lift a finding off the heuristic floor honestly.
//
// # Why refutations are not recorded here
//
// The structural path also refutes — a resource whose property the pattern
// could not see is not reported at all — and none of those produce a claim,
// deliberately. A refutation in this model attaches to a candidate, and there
// is no candidate: the finding was never created. That is different from the
// secrets refiners, which drop a candidate that existed and must say why. What
// is lost is visible in the finding count and in nothing else, which is the
// same place a false positive's removal has always been visible.
func (a *Analyzer) recordStructuralClaims(path string, fs []findings.Finding) {
	if a.reasoning == nil {
		return
	}
	for i := range fs {
		claim := fs[i].Metadata[rules.StructuralClaimKey]
		if claim == "" {
			continue
		}
		subject := reasoning.Candidate(fs[i].RuleID, path,
			fs[i].Location.StartLine, fs[i].Location.StartColumn)
		a.reasoning.Support(subject, evidence.KindStatic, "nox-scan", "iac", claim, nil)
	}
}

// ScanFile delegates to the underlying rules engine to scan the given file
// content and returns any IaC-related findings.
func (a *Analyzer) ScanFile(path string, content []byte) ([]findings.Finding, error) {
	results, err := a.engine.ScanFile(path, content)
	if err != nil {
		return nil, err
	}
	// Each filter is handed a recorder rather than dropping silently.
	//
	// These three shipped as bare `continue`s, which is exactly the pattern
	// core/reasoning was built to end — "the finding and the reason for
	// dropping it both discarded in the same statement". A refiner that drops
	// the wrong thing then produces a result indistinguishable from one that
	// had nothing to drop, and the stage accounting that found this reported
	// IaC as refuting nothing while it was quietly removing findings on every
	// scan.
	drop := a.refuter(path)
	out := dropArtifactsWhenAlways(results, content, drop)
	out = dropMatchesInComments(path, out, content, drop)
	out = dropKindReferences(path, out, content, drop)
	embedded, err := a.scanEmbedded(path, content, out)
	if err != nil {
		return nil, err
	}
	out = append(out, embedded...)
	a.recordStructuralClaims(path, out)
	return out, nil
}

// dropMatchesInComments removes findings whose match lies entirely inside a
// comment.
//
// An IaC rule's evidence is configuration. A rule keyword written in a comment
// is prose ABOUT configuration, and prose configures nothing: a manifest that
// says
//
//	# This comment mentions PodDisruptionBudget and nothing else.
//
// reported IAC-395, "K8s defines PodDisruptionBudget (positive)", against a
// ConfigMap. Kubernetes and Terraform files are heavily commented, and the
// comments name exactly the resource kinds and property names the rules match,
// so every explanatory line in a manifest was a candidate finding — landing on
// the files operators read most. Issue #588.
//
// This is the IaC half of a refinement the secrets analyzer has had since
// srccontext.go: `lexctx` is the single source of truth for lexical context,
// and `WithinComments` is the same primitive that path uses. The rules
// themselves need no change, which is the point — the comment question is
// lexical, not per-rule, and answering it once is why lexctx exists.
//
// Unlike secrets, there is no carve-out here. That analyzer deliberately keeps
// comment matches for PROVIDER rules, because a credential pasted into a
// comment is a real leak: the token itself is the evidence, wherever it sits.
// No IaC rule has that property. A Deployment named in a comment is not a
// Deployment, and a commented-out `privileged: true` is not privileged.
//
// The span test is strict — every non-blank byte the match covers must be
// comment — so a match that begins in code and runs into a trailing comment is
// kept. That asymmetry is deliberate: this filter removes findings, and the
// direction it must never fail in is dropping one that is partly real.
func dropMatchesInComments(path string, in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	if len(in) == 0 {
		return in
	}
	lang := configLang(path)
	if lang == lexctx.LangUnknown {
		return in
	}

	kept := in[:0]
	for _, f := range in {
		start := lexctx.LineColToOffset(content, f.Location.StartLine, f.Location.StartColumn)
		end := lexctx.LineColToOffset(content, f.Location.EndLine, f.Location.EndColumn)
		if end <= start {
			end = start + 1
		}
		if lexctx.WithinComments(lang, content, start, end) {
			drop(f, "the match lies entirely inside a comment, which is prose about "+
				"configuration rather than configuration")
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// kindReferenceFields are the Kubernetes fields whose value POINTS AT another
// object. A `kind:` nested under one of them names something else; it does not
// declare the document it sits in.
//
// This is an allowlist rather than a depth test, and that distinction is the
// whole fix. Indentation would be cheaper and, on the ten-repo corpus, exactly
// right: 34 of 36 IAC-131 matches sit at column 0 and both nested ones are
// references. It is also wrong, because a `kind: List` holds real objects
// indented under `items:` — a depth rule deletes every workload in one, and no
// corpus repo contains a List, so nothing would have caught it.
// r13_workloads_inside_a_list.yaml is that case.
//
// An allowlist fails toward reporting: a reference field nobody listed keeps
// producing a finding, which is noise. A depth rule fails toward silence.
var kindReferenceFields = map[string]bool{
	"scaleTargetRef":              true, // HorizontalPodAutoscaler -> workload
	"targetRef":                   true, // ServiceMonitor, Gateway API, Flagger
	"roleRef":                     true, // RoleBinding -> Role
	"subjects":                    true, // RoleBinding -> ServiceAccount/User
	"ownerReferences":             true, // any object -> its controller
	"crossVersionObjectReference": true, // autoscaling/v1 HPA
	"resourceRef":                 true, // Crossplane and friends
	"targetService":               true,
	"backendRef":                  true, // Gateway API HTTPRoute
	"parentRefs":                  true, // Gateway API
}

// dropKindReferences removes findings anchored to a `kind:` line that names
// another object rather than declaring this one.
//
// IAC-131 matched `kind\s*:\s*Deployment` anywhere in a YAML file, so a
// HorizontalPodAutoscaler reported "Kubernetes workload detected - verify
// NetworkPolicy exists" because it names the Deployment it scales. The document
// is an autoscaler: no pod template, no containers, nothing the rule is about.
// Issue #590.
//
// Two rules with the same defect were already removed by retiring them into
// structural survivors (#591) — IAC-183 and IAC-176, 17 findings on podinfo
// alone. IAC-131 has no structural survivor to retire into, so the reference
// test is applied directly.
//
// The check is deliberately narrow: only findings whose own matched line is a
// `kind:` mapping entry are considered, and only when the nearest enclosing key
// is a known reference field. A rule that matched something else on that line
// is untouched.
func dropKindReferences(path string, in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	if len(in) == 0 || configLang(path) != lexctx.LangYAML {
		return in
	}

	var lines []string
	kept := in[:0]
	for _, f := range in {
		if lines == nil {
			lines = strings.Split(string(content), "\n")
		}
		if isKindReference(lines, f.Location.StartLine) {
			drop(f, "the `kind:` on this line sits under a reference field, so it names "+
				"another object rather than declaring this one")
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// isKindReference reports whether the 1-based line is a `kind:` entry sitting
// under a field that points at another object.
func isKindReference(lines []string, line int) bool {
	if line < 1 || line > len(lines) {
		return false
	}
	trimmed := strings.TrimSpace(lines[line-1])
	// A list item declares the object it introduces: `- kind: Deployment` inside
	// `subjects:` is a reference, but the leading dash is part of the entry, so
	// strip it before testing the key.
	trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "-"))
	if !strings.HasPrefix(trimmed, "kind:") {
		return false
	}
	return kindReferenceFields[enclosingKey(lines, line)]
}

// configLang resolves the lexer language for an IaC file.
//
// It cannot use lexctx.LangFromPath, and the reason is written into that
// function: LangYAML and LangDockerfile are deliberately NOT mapped there,
// because the secrets, taint, ai and agentflow analyzers all gate on
// LangFromPath and mapping .yaml would silently change their behaviour on
// every such file. The languages exist and Classify handles them; only the
// path lookup withholds them. So this analyzer answers the question for its
// own files and changes nothing for anyone else.
//
// Terraform is absent because lexctx has no HCL lexer. `.tf` comments are
// therefore still matched, and issue #588 stays open for them: a filter that
// guessed at HCL comment syntax would be removing findings on a lexer nobody
// wrote, which is the direction that hides vulnerabilities.
func configLang(path string) lexctx.Lang {
	switch strings.ToLower(filepath.Ext(path)) {
	case ".yaml", ".yml":
		return lexctx.LangYAML
	}
	base := filepath.Base(path)
	if base == "Dockerfile" || base == "Containerfile" ||
		strings.HasPrefix(base, "Dockerfile.") || strings.HasPrefix(base, "Containerfile.") {
		return lexctx.LangDockerfile
	}
	return lexctx.LangUnknown
}

// dropArtifactsWhenAlways removes IAC-348 findings whose `when: always` sits
// inside an `artifacts:` block.
//
// The rule matches the two words with a bare pattern, but everything it says
// is about JOB EXECUTION: "CI job runs regardless of previous failures", and a
// remediation warning that running deployment jobs after test failures can push
// broken code to production. Under `artifacts:` the same words mean upload the
// artifacts even when the job failed — which for a scanner is the entire point,
// since the run you most want the SARIF from is the one that failed the gate.
// nox's own GitLab example was flagged for doing the right thing.
//
// Dropped rather than downgraded, for the same reason as the Ansible rules on
// GitHub Actions files: a lower-severity finding still puts a rule in front of
// an operator that could not apply here.
//
// Block membership is decided by indentation — the nearest enclosing key at a
// shallower indent — which is enough for the mapping shapes CI files use and
// needs no YAML parser on this path.
func dropArtifactsWhenAlways(in []findings.Finding, content []byte, drop refuteFunc) []findings.Finding {
	if len(in) == 0 {
		return in
	}
	var lines []string
	kept := in[:0]
	for _, f := range in {
		if f.RuleID != "IAC-348" {
			kept = append(kept, f)
			continue
		}
		if lines == nil {
			lines = strings.Split(string(content), "\n")
		}
		if enclosingKey(lines, f.Location.StartLine) == "artifacts" {
			drop(f, "`if: always()` inside an artifacts block uploads diagnostics on "+
				"failure, which is the intended use rather than a skipped gate")
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// enclosingKey returns the mapping key that encloses a 1-based line, or "" if
// the line is top-level or out of range.
func enclosingKey(lines []string, line int) string {
	if line < 1 || line > len(lines) {
		return ""
	}
	indent := func(s string) int { return len(s) - len(strings.TrimLeft(s, " 	")) }
	target := indent(lines[line-1])
	for i := line - 2; i >= 0; i-- {
		l := lines[i]
		trimmed := strings.TrimSpace(l)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if indent(l) >= target {
			continue
		}
		key, _, found := strings.Cut(trimmed, ":")
		if !found {
			return ""
		}
		return strings.TrimSpace(strings.TrimPrefix(key, "- "))
	}
	return ""
}

// ScanArtifacts reads each artifact file from disk, scans it for IaC
// misconfigurations, and collects all findings into a deduplicated FindingSet.
// GitHub Actions workflow findings receive a context-aware post-pass that
// downgrades well-known false positives (ephemeral test DB credentials,
// permissions paired with their justifying consumer action).
func (a *Analyzer) ScanArtifacts(ctx context.Context, artifacts []discovery.Artifact) (*findings.FindingSet, error) {
	fs := findings.NewFindingSet()

	// The index is what makes a cross-resource rule answerable at all in a real
	// manifest tree: a Helm chart or a kustomize base puts each object in its
	// own file, so a Deployment's PodDisruptionBudget is almost never in the
	// same document set. Built first, from the same bytes the scan reads, and
	// consulted only to REFUTE — see structural.Index.
	index := structural.NewIndex()
	contents := make(map[string][]byte, len(artifacts))

	var collected []findings.Finding
	for _, artifact := range artifacts {
		// Honour cancellation between artifacts — see the note in the secrets
		// analyzer: nothing else in this loop consults ctx.
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		content, err := os.ReadFile(artifact.AbsPath)
		if err != nil {
			return nil, fmt.Errorf("reading artifact %s: %w", artifact.Path, err)
		}

		results, err := a.ScanFile(artifact.Path, content)
		if err != nil {
			return nil, fmt.Errorf("scanning artifact %s: %w", artifact.Path, err)
		}

		index.Add(artifact.Path, content)
		contents[artifact.Path] = content
		collected = append(collected, results...)
	}

	collected = a.refuteCompanionsFoundInOtherFiles(index, contents, collected)

	// GitHub Actions context downgrades are applied by the scan pipeline across
	// EVERY analyzer's output (core/scan.go), not just IaC's. Applying them a
	// second time here was redundant, and — before finding metadata was copied
	// per-finding — the second pass re-wrote a shared map and contaminated
	// unrelated findings. The pipeline is the single place they are applied.
	for i := range collected {
		fs.Add(collected[i])
	}

	fs.Deduplicate()
	return fs, nil
}

// refuteCompanionsFoundInOtherFiles drops a cross-resource finding when the
// companion it asked for exists in another file the same scan read.
//
// # Why this is a post-pass and not part of the verdict
//
// The per-file structural verdict is the authoritative one, and it must stay
// answerable from a single file: `ScanFile` is what the MCP server and the LSP
// call, and they hand over one buffer with no tree behind it. So the cross-file
// answer is layered on top, where it can only ever REMOVE a finding the
// single-file pass already produced.
//
// That direction is the whole safety argument. A scan that read more files may
// clear a resource it would otherwise flag; it may never flag one it would
// otherwise clear. The reverse would make a finding depend on which directory
// the operator pointed at, which is the kind of instability that teaches people
// to ignore a scanner.
//
// A finding is reconsidered only when its rule carries a companion descriptor
// AND the finding sits on a resource this pass can re-resolve by line. Anything
// else is left exactly as it was.
func (a *Analyzer) refuteCompanionsFoundInOtherFiles(index *structural.Index, contents map[string][]byte, in []findings.Finding) []findings.Finding {
	if index == nil || index.Len() < 2 {
		// One file cannot contain a cross-FILE companion, so there is nothing
		// this pass could establish that the per-file verdict did not.
		return in
	}

	out := in[:0:0]
	for i := range in {
		f := &in[i]
		rule, ok := a.engine.Rules().ByID(f.RuleID)
		if !ok || len(rule.AbsenceCompanionTypes) == 0 {
			out = append(out, in[i])
			continue
		}
		content, ok := contents[f.Location.FilePath]
		if !ok {
			out = append(out, in[i])
			continue
		}
		subject, ok := structural.ResourceAt(content, f.Location.StartLine)
		if !ok {
			// The finding came from the text path, which reports at an anchor
			// rather than a resource declaration. Nothing to re-resolve.
			out = append(out, in[i])
			continue
		}

		hit, found := index.CompanionElsewhere(subject, f.Location.FilePath, structural.Companion{
			Types: rule.AbsenceCompanionTypes,
			Link:  structural.Link(rule.AbsenceCompanionLink),
			Path:  rule.AbsenceCompanionPath,
		})
		if !found {
			// The finding stands. But its claim was written by the per-file
			// pass and says the DOCUMENT SET declares no such companion, which
			// is true of that file and misleading once a wider scan has seen
			// one that simply does not cover this resource. Saying which it was
			// costs nothing and is the difference between "nothing of this kind
			// exists here" and "one exists and it protects something else".
			if index.HasType(rule.AbsenceCompanionTypes, f.Location.FilePath) {
				noteCompanionScannedElsewhere(&in[i], rule.AbsenceCompanionTypes[0])
			}
			out = append(out, in[i])
			continue
		}

		// The reason for a suppression has to survive the suppression.
		a.refuteCrossFile(f, hit)
	}
	return out
}

// refuteFunc records why one finding was dropped. A refiner takes it rather
// than reaching for the store, so the recording cannot be forgotten at one call
// site and present at another — the shape that let three filters ship silent.
type refuteFunc func(f findings.Finding, reason string)

// refuter returns the recorder for findings dropped in path.
//
// It returns a working function even when nothing is recording, so a refiner
// never branches on whether anybody asked for reasoning. That is the same
// property that makes a nil reasoning.Store safe to call: a guard written the
// wrong way at one site is how a refiner silently stops recording.
func (a *Analyzer) refuter(path string) refuteFunc {
	return func(f findings.Finding, reason string) {
		if a.reasoning == nil {
			return
		}
		subject := reasoning.Candidate(f.RuleID, path,
			f.Location.StartLine, f.Location.StartColumn)
		a.reasoning.Refute(subject, evidence.KindStatic, "nox-scan", "iac", reason)
	}
}

// refuteCrossFile records why a finding was dropped by the cross-file pass.
func (a *Analyzer) refuteCrossFile(f *findings.Finding, hit structural.Hit) {
	if a.reasoning == nil {
		return
	}
	subject := reasoning.Candidate(f.RuleID, f.Location.FilePath,
		f.Location.StartLine, f.Location.StartColumn)
	a.reasoning.Refute(subject, evidence.KindStatic, "nox-scan", "iac",
		hit.CrossFileStatement())
}

// noteCompanionScannedElsewhere amends a surviving finding's structural claim
// so it distinguishes an absent companion from an unrelated one.
func noteCompanionScannedElsewhere(f *findings.Finding, companionType string) {
	claim := f.Metadata[rules.StructuralClaimKey]
	if claim == "" {
		return
	}
	if f.Metadata == nil {
		f.Metadata = map[string]string{}
	}
	f.Metadata[rules.StructuralClaimKey] = claim +
		"; another " + companionType + " was found among the manifests scanned, and it does not cover this resource"
}
