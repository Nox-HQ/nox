// Package explain answers, for one finding, the eight questions a developer
// actually has when they are looking at it.
//
// It is Milestone 9.3, and it is deterministic on purpose. `nox explain` uses a
// language model to write prose about a finding, which is useful and is a
// different thing: this reads only what the scan established, so the same
// finding and the same evidence always produce the same answers, and every
// sentence can be traced to a claim, a capability state or a rule's own
// metadata.
//
// # The discipline that shapes every answer
//
// Two of the eight are questions nox usually cannot answer, and those are the
// ones worth getting right. "What was not evaluated?" is a gap, not a limit,
// and a scanner that stays silent about it lets a reader infer that everything
// was looked at. "Does it affect this application?" is the question every
// developer actually asks, and the honest answer is very often that nobody
// knows — which must never be phrased as though the answer were no.
//
// So no answer here asserts safety. The vocabulary is checked by test, in both
// directions the wording could overstate.
package explain

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nox-hq/nox-core/evidence"
	"github.com/nox-hq/nox/core/adjudicate"
	"github.com/nox-hq/nox/core/capability"
	"github.com/nox-hq/nox/core/catalog"
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/reach"
)

// Explanation is the eight answers, in the order a person reads them.
//
// Every field is a sentence or a list of sentences, never a code. A consumer
// that wants the underlying state reads the finding and the artifact; this is
// the layer that says what they mean.
type Explanation struct {
	Fingerprint string `json:"fingerprint"`
	RuleID      string `json:"rule_id"`
	Location    string `json:"location"`

	// Observed answers "what was observed?" — the thing in the code, not the
	// judgement about it.
	Observed string `json:"observed"`
	// WhyItMatters answers "why does nox think it matters?" — the rule's own
	// reason for existing.
	WhyItMatters string `json:"why_it_matters"`
	// Supports answers "what supports that?" — the claims that argue for it.
	Supports []string `json:"supports"`
	// Against answers "what argues against it?" — claims that argue the other
	// way, and evidence deliberately withheld. Empty means nothing did, which
	// is different from nothing having been asked.
	Against []string `json:"against"`
	// NotEvaluated answers "what was not evaluated?" — the analyses that never
	// reached a conclusion here, so their silence is not read as a clearance.
	NotEvaluated []string `json:"not_evaluated"`
	// PotentialImpact answers "what is the potential impact?" — the
	// consequence IF the finding is real, which is severity's own meaning and
	// deliberately not merged with how sure anyone is.
	PotentialImpact string `json:"potential_impact"`
	// AffectsThisApplication answers "does it affect this application?" — the
	// applicability ladder, and where it stopped climbing.
	AffectsThisApplication string `json:"affects_this_application"`
	// WhatToDo answers "what should I do?" — remediation, or an honest
	// statement that the rule carries none.
	WhatToDo string `json:"what_to_do"`
}

// Inputs are everything an explanation draws on.
type Inputs struct {
	Finding  findings.Finding
	Ledger   evidence.Ledger
	Subject  evidence.Subject
	Coverage *capability.Coverage
	// Registry is what this installation provides, needed to tell an open
	// question something could answer from one nothing can.
	Registry *capability.Registry
	Rule     catalog.RuleMeta
}

// Explain answers the eight questions for one finding.
func Explain(in Inputs) Explanation {
	f := in.Finding
	e := Explanation{
		Fingerprint: f.Fingerprint,
		RuleID:      f.RuleID,
		Location:    location(f),
	}
	e.Observed = observed(f)
	e.WhyItMatters = whyItMatters(f, in.Rule)
	e.Supports, e.Against = argument(in.Ledger, in.Subject)
	e.NotEvaluated = append(limitationLines(f), notEvaluated(in.Coverage, in.Subject)...)
	e.PotentialImpact = potentialImpact(f, in.Rule)
	e.AffectsThisApplication = affectsThisApplication(f)
	e.WhatToDo = whatToDo(in.Rule) + nextEvidence(in)
	return e
}

func location(f findings.Finding) string {
	if f.Location.FilePath == "" {
		return "the repository as a whole"
	}
	if f.Location.StartLine > 0 {
		return fmt.Sprintf("%s:%d", f.Location.FilePath, f.Location.StartLine)
	}
	return f.Location.FilePath
}

// observed reports what was seen, separately from what it was taken to mean.
//
// It deliberately does NOT print the matched text. Metadata["match"] holds the
// raw matched value — the secrets refiner reads it to decide whether a value is
// a documentation placeholder — so on a secrets finding it is the credential
// itself. This output lands in terminals and CI logs, and a tool whose stated
// posture is that it never uploads source code has no business printing a live
// token to stdout because the explanation read better with it. The location
// says where to look; the reader has the file.
func observed(f findings.Finding) string {
	base := f.Message
	if base == "" {
		base = fmt.Sprintf("%s matched", f.RuleID)
	}
	return fmt.Sprintf("%s at %s.", base, location(f))
}

// whyItMatters gives the rule's reason for existing, and says so when it has
// none to give.
//
// Many catalogue descriptions restate the finding's own message — SEC-003's is
// "GitHub Personal Access Token detected", which is exactly what was observed.
// Repeating it here would answer "why does this matter?" with "because it
// happened", which is the shape of an explanation without being one. Better to
// say the catalogue is thin: that is true, it tells the reader not to keep
// looking for a reason that is not there, and it is actionable by whoever
// maintains the rule.
func whyItMatters(f findings.Finding, rule catalog.RuleMeta) string {
	cwe := cweOf(f, rule)
	desc := strings.TrimRight(rule.Description, ".")

	if desc == "" {
		return fmt.Sprintf("Rule %s carries no catalogue description, so the message "+
			"above is all it says for itself.%s", f.RuleID, cweSuffix(cwe))
	}
	if restates(desc, f.Message) {
		return fmt.Sprintf("Rule %s's description restates the observation rather than "+
			"giving a reason for it.%s", f.RuleID, cweSuffix(cwe))
	}
	if cwe != "" {
		return fmt.Sprintf("%s (%s).", desc, cwe)
	}
	return desc + "."
}

// restates reports whether a rule description says the same thing as the
// finding's message, ignoring case and trailing punctuation.
func restates(desc, message string) bool {
	norm := func(s string) string {
		return strings.ToLower(strings.TrimRight(strings.TrimSpace(s), ".!"))
	}
	return norm(desc) == norm(message)
}

func cweSuffix(cwe string) string {
	if cwe == "" {
		return ""
	}
	return " It is classified as " + cwe + "."
}

func cweOf(f findings.Finding, rule catalog.RuleMeta) string {
	if rule.CWE != "" {
		return rule.CWE
	}
	return f.Metadata["cwe"]
}

// argument splits the ledger into what argued for the finding and what argued
// against it, in the ledger's own words.
//
// Claims withheld — recorded with unknown polarity, which is how a
// config-driven removal is filed — are listed under "against" with their own
// framing. They are not refutations and must not read as ones: something was
// set aside without an argument being made either way, and a reader who cannot
// see that has lost the distinction the polarity model exists for.
func argument(l evidence.Ledger, s evidence.Subject) (supports, against []string) {
	sub := l.About(s)
	for _, c := range sub.Claims {
		line := fmt.Sprintf("%s (%s)", c.Statement, c.Kind)
		if src := c.Provenance.Source; src != "" {
			line = fmt.Sprintf("%s (%s, reported by %s)", c.Statement, c.Kind, src)
		}
		if !c.Live() {
			line += " — withdrawn, and carries no weight"
		}
		switch {
		case c.Refutes():
			against = append(against, line)
		case c.Supports():
			supports = append(supports, line)
		default:
			against = append(against, "set aside without an argument either way: "+line)
		}
	}
	if len(supports) == 0 {
		supports = append(supports, "Nothing was recorded in support of this finding beyond the rule firing.")
	}
	if len(against) == 0 {
		against = append(against, "Nothing was recorded against it. That is not the same as "+
			"nothing having been looked for — see what was not evaluated.")
	}
	return supports, against
}

// notEvaluated lists the analyses that reached no conclusion about this
// subject, so their silence is not mistaken for a clean result.
//
// A capability nothing implements is reported differently from one that ran and
// could not tell, because the reader's next step differs: install something, or
// look at why it could not tell.
func notEvaluated(cov *capability.Coverage, s evidence.Subject) []string {
	if cov == nil {
		return []string{"No capability coverage was recorded for this scan, so nothing " +
			"here can say which analyses ran."}
	}
	var out []string
	for _, c := range capability.All() {
		switch cov.State(s, c) {
		case capability.Positive, capability.Negative:
			continue
		case capability.Unsupported:
			out = append(out, fmt.Sprintf("%s: no analysis on this installation can establish it.", c))
		case capability.TimedOut:
			out = append(out, fmt.Sprintf("%s: the analysis started and did not finish.", c))
		case capability.Unknown:
			out = append(out, fmt.Sprintf("%s: the analysis ran and could not determine anything.", c))
		default:
			out = append(out, fmt.Sprintf("%s: nothing asked this question here.", c))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		out = []string{"Every analysis nox has reached a conclusion about this finding."}
	}
	return out
}

// limitationLines reports the constructs in this file that defeat static
// analysis, so silence about the rest of the file reads as what it is.
//
// It appears under "what was not evaluated" because that is the question it
// answers. A capability state says an analysis reached no conclusion; this says
// why one could not be reached here, which is the difference between a reader
// installing a plugin and a reader understanding that the code is not
// statically analysable at this point.
func limitationLines(f findings.Finding) []string {
	raw := f.Metadata["analysis_limitations"]
	if raw == "" {
		return nil
	}
	var out []string
	for _, name := range strings.Split(raw, ",") {
		l := reach.Limitation(strings.TrimSpace(name))
		out = append(out, "this file defeats static analysis — "+l.Describe()+
			" — so any analysis of it is incomplete, and nothing here was ruled out")
	}
	return out
}

// potentialImpact is severity's own meaning: the consequence IF the finding is
// real. It is deliberately not merged with confidence — how bad it would be and
// how sure anyone is are different questions, and a single blended number
// answers neither.
func potentialImpact(f findings.Finding, rule catalog.RuleMeta) string {
	sev := string(f.Severity)
	if sev == "" {
		sev = "unrated"
	}
	s := fmt.Sprintf("Rated %s severity, which is the consequence if this finding is real — "+
		"not a statement about how likely that is.", sev)
	if cwe := cweOf(f, rule); cwe != "" {
		s += fmt.Sprintf(" Classified as %s.", cwe)
	}
	return s
}

// affectsThisApplication answers the question every developer actually asks,
// and answers "nobody established that" when nobody did.
//
// The wording never resolves to a clearance. A dependency whose vulnerable
// symbol is not linked is reported as not impacting THROUGH THAT PATH, with the
// path stated, because the claim is about what was checked rather than about
// the application being fine.
func affectsThisApplication(f findings.Finding) string {
	outcome := f.Metadata["applicability"]
	reached := f.Metadata["applicability_reached"]
	stopped := f.Metadata["applicability_stopped_at"]
	because := f.Metadata["applicability_because"]

	// The reachability chain, when the dependency analyzer answered at some
	// level of it. Reported as the LEVEL it established, never as "reachable":
	// linker evidence establishes that an affected import is linked, which is
	// several propositions short of an attacker being able to reach it.
	if lvl, out := f.Metadata["reach_level"], f.Metadata["reach_outcome"]; lvl != "" && out != "" {
		scope := f.Metadata["reach_scope"]
		switch out {
		case "established":
			return fmt.Sprintf("%s holds: %s. That is one step on the chain from an "+
				"advisory to an exploit, not the whole of it — whether anything calls "+
				"it, and whether an attacker can reach that, were not established.",
				lvl, scope)
		case "refuted":
			return fmt.Sprintf("%s does not hold within the scope searched (%s). "+
				"Nothing here rules out another build or another path.", lvl, scope)
		default:
			return fmt.Sprintf("%s could not be determined (%s). Unknown, which is not "+
				"the same as no.", lvl, scope)
		}
	}

	switch outcome {
	case "":
		// Most findings are in this repository's own code, where the question
		// is not "does a dependency reach you" but "is this line yours". Saying
		// so beats inventing a ladder position for it.
		if f.Location.FilePath != "" {
			return "This is in code in this repository, so it is present by definition. " +
				"Whether it is reachable at runtime was not established."
		}
		return "Applicability was not assessed for this finding."
	case "not_impacting":
		return fmt.Sprintf("The argument reached %s and then stopped: %s. On that path it does "+
			"not impact this application. Nothing here rules out another path.", reached, because)
	case "undetermined":
		return fmt.Sprintf("The argument got as far as %s and could not go further, because %s "+
			"could not be established (%s). Whether it affects this application is unknown, "+
			"which is not the same as no.", reached, stopped, because)
	default:
		return fmt.Sprintf("Applicability reached %s.", reached)
	}
}

// nextEvidence names the cheapest open question something on this installation
// could answer, appended to the remediation.
//
// It is the actionable half of "what was not evaluated". That field says which
// questions are open; this says which one to take first, and only ever
// recommends something the reader can actually do — a gap nothing can fill is
// worth naming as a limit but is not a next step.
func nextEvidence(in Inputs) string {
	if in.Coverage == nil || in.Registry == nil {
		return ""
	}
	gaps := adjudicate.MissingEvidence(in.Coverage, in.Registry, in.Subject)
	next, ok := adjudicate.CheapestAvailable(gaps)
	if !ok {
		return ""
	}
	return " The cheapest thing that would move this conclusion is " +
		string(next.Capability) + ": " + next.Question
}

func whatToDo(rule catalog.RuleMeta) string {
	if rule.Remediation != "" {
		s := strings.TrimRight(rule.Remediation, ".") + "."
		if len(rule.References) > 0 {
			s += " See: " + strings.Join(rule.References, ", ") + "."
		}
		return s
	}
	return "This rule carries no remediation guidance. Treat the evidence above as the " +
		"input to your own judgement rather than waiting for nox to make it."
}
