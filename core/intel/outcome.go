package intel

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"unicode"

	"github.com/nox-hq/nox/core/findings"
)

// OutcomeTermsVersion names the terms for outcome reports. A separate document
// and a separate acceptance from the scan terms: an observation shares a fact
// about a package, an outcome report shares one project's dependency findings
// over time. Changing OutcomeTerms without changing this string is caught by a
// test.
const OutcomeTermsVersion = "outcomes-2026-11"

// OutcomeSchemaVersion is the outcome wire contract this build speaks.
const OutcomeSchemaVersion = 1

// OutcomeTerms is what an operator agrees to before a scan sends an outcome
// report.
//
// REQUIRES OWNER REVIEW BEFORE RELEASE: this is user-facing terms text.
const OutcomeTerms = `NOX Intelligence outcome terms, version outcomes-2026-11

Outcome reports are optional and off by default. They need contribution on
(scan.intelligence.contribute: true, with the contribution terms accepted),
scan.intelligence.outcomes: true, AND these terms accepted on this machine.

Why
  A vulnerability nox could not decide is ordered by what is known about the
  advisory, never about your application. Learning which ones matter needs to
  see what happened next: a finding that went away after an upgrade, across
  many projects. One report per scan makes that possible.

What is sent, per scan
  Only the fields printed by "nox intel allowlist --outcomes": a pseudonym for
  this project, and for each vulnerable dependency its ecosystem, name, exact
  version and advisory id, and what nox decided about it (impacting, not
  impacting or undetermined, the step it reached and why it stopped, and
  whether your own source imports the package). Plus your reporter id, a
  timestamp, the nox version and the terms you accepted.

The project pseudonym
  An HMAC of the repository's first commit, keyed by a secret that stays on
  this machine. The same repository scanned here always gives the same
  pseudonym; anyone else scanning it gets a different one; nobody can turn it
  back into a repository. No pseudonym, no report: a shallow clone or a
  directory outside git sends nothing.

What is never sent
  Source code, file names or paths, the repository's name or URL, commit
  hashes, branch names, route paths, symbol names, secrets or prompts.

The honest limit
  A pseudonym together with packages and versions over time describes a
  technology stack. That is why this is a separate opt-in, why the service
  publishes only models and aggregates over many projects and never anything
  per project, and why you can delete it.

What the service does with it
  Keeps one report per project and day, deletes it after the retention window
  (90 days by default), and uses the reports to train and measure models that
  order undecided findings. Nothing per project is published.

How to erase and withdraw
  "nox intel forget" deletes your outcome reports along with your other
  contributions and turns both off on this machine. Withdraw here, without
  contacting the service, with "nox intel consent outcomes withdraw".

If these terms change, outcome reports pause until you accept the new version.
`

// OutcomeConsentPath is where the acceptance lives, beside the scan consent.
func OutcomeConsentPath(saltPath string) string {
	if saltPath == "" {
		saltPath = DefaultSaltPath()
	}
	return filepath.Join(filepath.Dir(saltPath), "intel-outcome-consent.json")
}

// LoadOutcomeConsent reports the status of the outcome acceptance.
func LoadOutcomeConsent(saltPath string) (ConsentStatus, Consent) {
	b, err := os.ReadFile(OutcomeConsentPath(saltPath))
	if err != nil {
		return ConsentNone, Consent{}
	}
	var c Consent
	if json.Unmarshal(b, &c) != nil || c.TermsVersion == "" {
		return ConsentNone, Consent{}
	}
	if c.TermsVersion != OutcomeTermsVersion {
		return ConsentStale, c
	}
	return ConsentGranted, c
}

// RecordOutcomeConsent stores the acceptance of the current outcome terms.
func RecordOutcomeConsent(saltPath, at string) error {
	p := OutcomeConsentPath(saltPath)
	b, err := json.Marshal(Consent{TermsVersion: OutcomeTermsVersion, AcceptedAt: at})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("creating consent directory: %w", err)
	}
	return os.WriteFile(p, b, 0o600)
}

// WithdrawOutcomeConsent removes the acceptance; withdrawing nothing is fine.
func WithdrawOutcomeConsent(saltPath string) error {
	if err := os.Remove(OutcomeConsentPath(saltPath)); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("withdrawing outcome consent: %w", err)
	}
	return nil
}

// projectLabel separates the pseudonym's HMAC from the reporter id's and the
// deletion key's, so none of the three reveals anything about another.
const projectLabel = "nox-intelligence-project-v1\x00"

// ProjectPseudonym is this installation's name for a repository: an HMAC,
// under the private salt, of the repository's root commit. Stable for one
// repository here, different on every other installation, irreversible.
func ProjectPseudonym(saltPath, rootCommit string) (string, error) {
	if strings.TrimSpace(rootCommit) == "" {
		return "", errors.New("no root commit")
	}
	if saltPath == "" {
		saltPath = DefaultSaltPath()
	}
	salt, err := loadOrCreateSalt(saltPath)
	if err != nil {
		return "", err
	}
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(projectLabel))
	mac.Write([]byte(strings.TrimSpace(rootCommit)))
	return hex.EncodeToString(mac.Sum(nil)), nil
}

// OutcomeReport is the wire form of POST /v1/outcomes. Every field is listed
// by OutcomeAllowlist, and a test holds the two together.
type OutcomeReport struct {
	SchemaVersion    int              `json:"schema_version"`
	ConsentVersion   string           `json:"consent_version"`
	OutcomeTerms     string           `json:"outcome_terms"`
	ReporterID       string           `json:"reporter_id"`
	DeletionVerifier string           `json:"deletion_verifier,omitempty"`
	Project          string           `json:"project"`
	ObservedAt       string           `json:"observed_at"`
	ToolVersion      string           `json:"tool_version,omitempty"`
	Findings         []OutcomeFinding `json:"findings"`
}

// OutcomeFinding is one dependency finding, minimised. There is no severity:
// a not-impacting finding is demoted to info, so its severity is the verdict
// again, and the service already has the advisory's own.
type OutcomeFinding struct {
	Ecosystem     string `json:"ecosystem"`
	Package       string `json:"package"`
	Version       string `json:"version"`
	Advisory      string `json:"advisory"`
	Applicability string `json:"applicability"`
	Reached       string `json:"reached,omitempty"`
	StoppedAt     string `json:"stopped_at,omitempty"`
	Because       string `json:"because,omitempty"`
	Imported      string `json:"imported,omitempty"`
}

// OutcomeAllowlist is every field an outcome report may carry.
func OutcomeAllowlist() []AllowedField {
	return []AllowedField{
		{"schema_version", "the outcome wire version (1)"},
		{"consent_version", "the contribution terms you accepted"},
		{"outcome_terms", "the outcome terms you accepted"},
		{"reporter_id", "this installation's opaque id, as on observations"},
		{"deletion_verifier", "a hash that lets only you erase your reports"},
		{"project", "HMAC of the repository's first commit under this machine's secret"},
		{"observed_at", "when the scan ran"},
		{"tool_version", "the nox build"},
		{"findings[].ecosystem", "package ecosystem, e.g. go, npm"},
		{"findings[].package", "the vulnerable package's name"},
		{"findings[].version", "the version this project resolves"},
		{"findings[].advisory", "the advisory id, e.g. GO-2023-1571"},
		{"findings[].applicability", "impacting, not_impacting or undetermined"},
		{"findings[].reached", "the applicability step nox reached"},
		{"findings[].stopped_at", "the step it stopped at"},
		{"findings[].because", "why it stopped, as a reason token"},
		{"findings[].imported", "yes or no: your own source imports the package"},
	}
}

// maxOutcomeFindings mirrors the service's bound; a report over it is refused
// whole, so the client trims to it and says so.
const maxOutcomeFindings = 5000

var (
	outEcosystemRE = regexp.MustCompile(`^[a-z][a-z0-9.-]{0,31}$`)
	outVersionRE   = regexp.MustCompile(`^[0-9A-Za-z][0-9A-Za-z.+_~-]{0,63}$`)
	outAdvisoryRE  = regexp.MustCompile(`^[A-Za-z][A-Za-z0-9._:-]{2,63}$`)
	outTokenRE     = regexp.MustCompile(`^[a-z][a-z0-9_]{0,63}$`)
	outVerdicts    = map[string]bool{"impacting": true, "not_impacting": true, "undetermined": true}
)

// DeriveOutcomeFindings reduces a scan's findings to outcome findings: one per
// dependency vulnerability, sorted, duplicates removed. A finding whose values
// would not pass the service's bounds is left out rather than sent, because a
// single bad value refuses the whole report. skipped counts what was left out
// (including anything over the size bound), so the caller can say so.
func DeriveOutcomeFindings(fs []findings.Finding) (out []OutcomeFinding, skipped int) {
	seen := map[OutcomeFinding]bool{}
	for _, f := range fs {
		if f.RuleID != "VULN-001" {
			continue
		}
		m := f.Metadata
		o := OutcomeFinding{
			Ecosystem:     m["ecosystem"],
			Package:       m["package"],
			Version:       m["version"],
			Advisory:      m["vuln_id"],
			Applicability: m["applicability"],
			Reached:       m["applicability_reached"],
			StoppedAt:     m["applicability_stopped_at"],
			Because:       m["applicability_because"],
		}
		switch m["dependency_imported"] {
		case "true":
			o.Imported = "yes"
		case "false":
			o.Imported = "no"
		}
		if !o.valid() {
			skipped++
			continue
		}
		if !seen[o] {
			seen[o] = true
			out = append(out, o)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].key() < out[j].key() })
	if len(out) > maxOutcomeFindings {
		skipped += len(out) - maxOutcomeFindings
		out = out[:maxOutcomeFindings]
	}
	return out, skipped
}

func (o OutcomeFinding) key() string {
	return strings.Join([]string{o.Ecosystem, o.Package, o.Version, o.Advisory, o.Applicability,
		o.Reached, o.StoppedAt, o.Because, o.Imported}, "\x00")
}

func (o OutcomeFinding) valid() bool {
	token := func(s string) bool { return s == "" || outTokenRE.MatchString(s) }
	return outEcosystemRE.MatchString(o.Ecosystem) &&
		o.Package != "" && len(o.Package) <= 256 && !strings.Contains(o.Package, "://") &&
		!strings.Contains(o.Package, `\`) &&
		strings.IndexFunc(o.Package, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0 &&
		outVersionRE.MatchString(o.Version) && outAdvisoryRE.MatchString(o.Advisory) &&
		outVerdicts[o.Applicability] && token(o.Reached) && token(o.StoppedAt) && token(o.Because)
}

// OutcomeReceipt is what the service says about an accepted report.
type OutcomeReceipt struct {
	Findings int `json:"findings"`
}

// SubmitOutcome sends one outcome report. It is always anonymous: an outcome
// report never carries the organisation token, because a project pseudonym
// joined to a seat would name whose project it is.
func (c *Client) SubmitOutcome(ctx context.Context, r OutcomeReport) (OutcomeReceipt, error) {
	var rec OutcomeReceipt
	if r.ConsentVersion == "" || r.OutcomeTerms == "" || r.Project == "" {
		return rec, errors.New("outcome report carries no consent, outcome terms or project; not sent")
	}
	if r.Findings == nil {
		r.Findings = []OutcomeFinding{}
	}
	body, err := json.Marshal(r)
	if err != nil {
		return rec, fmt.Errorf("marshalling outcome report: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/v1/outcomes", bytes.NewReader(body))
	if err != nil {
		return rec, err
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return rec, err
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusAccepted {
		var e struct {
			Error string `json:"error"`
			Code  string `json:"code"`
		}
		_ = json.NewDecoder(resp.Body).Decode(&e)
		if e.Error != "" {
			return rec, fmt.Errorf("outcome report refused (status %d, %s): %s", resp.StatusCode, e.Code, e.Error)
		}
		return rec, fmt.Errorf("outcome report refused with status %d", resp.StatusCode)
	}
	// 202 is the acceptance; the receipt only describes it. An unreadable one
	// must not turn an accepted report into a reported failure.
	_ = json.NewDecoder(resp.Body).Decode(&rec)
	return rec, nil
}
