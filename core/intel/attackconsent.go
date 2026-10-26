package intel

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

// AttackTermsVersion names the terms for contributing `nox attack` evidence. It
// is a separate document and a separate acceptance from the scan terms: a scan
// contribution shares a fact about a package, an attack contribution shares that
// you ran an exploit against your own system and what happened. Changing
// AttackTerms without changing this string is caught by a test.
const AttackTermsVersion = "attack-2026-10"

// AttackTerms is what an operator agrees to before `nox attack ... --contribute`
// sends anything.
//
// REQUIRES OWNER REVIEW BEFORE RELEASE: this is user-facing terms text.
const AttackTerms = `NOX Intelligence attack-evidence terms, version attack-2026-10

Contributing attack evidence is optional and off by default. It needs an
organisation token (NOX_INTEL_TOKEN) and --contribute on the command, and these
terms accepted on this machine.

Unlike a scan contribution, this is ATTRIBUTED. The service authenticates your
organisation and records the evidence against it (as a one-way pseudonym in the
shared record; never the organisation name). Two seats of one organisation are
one source.

What is sent, per executed run
  Only the fields printed by "nox intel allowlist --attack": the candidate
  fingerprint you name, the exploitability state the run reached, the kind of
  evidence, whether a deterministic oracle decided it, whether it
  reproduced, whether the benign control was sound, the samples/hits tally, the safety profile, a SHA-256 digest of
  the trace, the nox version and a timestamp.

What is never sent
  The target URL, host or IP address, the route, field names, payloads, the
  target's responses, canary values, file paths, source code, secrets, prompts,
  or the trace itself. The digest is one-way: only you can show which trace it
  was.

What the service does with it
  It stores the report against your organisation, shows an operator how many
  attested reporters reproduced a violation, and may raise YOUR organisation's
  own exposure view. It does not verify the run, does not treat it as evidence
  for anyone else, and it can never make a vulnerability CONFIRMED: a report is
  one organisation's account of its own system.

How to erase
  "nox intel forget --attested" (with NOX_INTEL_TOKEN) removes your
  organisation's contributions from the service. Withdraw here, without
  contacting the service, with "nox intel consent attack withdraw".

If these terms change, attack contribution pauses until you accept the new
version.
`

// AttackConsentPath is where the acceptance lives, beside the scan consent.
func AttackConsentPath(saltPath string) string {
	if saltPath == "" {
		saltPath = DefaultSaltPath()
	}
	return filepath.Join(filepath.Dir(saltPath), "intel-attack-consent.json")
}

// LoadAttackConsent reports the status of the attack-evidence acceptance.
func LoadAttackConsent(saltPath string) (ConsentStatus, Consent) {
	b, err := os.ReadFile(AttackConsentPath(saltPath))
	if err != nil {
		return ConsentNone, Consent{}
	}
	var c Consent
	if json.Unmarshal(b, &c) != nil || c.TermsVersion == "" {
		return ConsentNone, Consent{}
	}
	if c.TermsVersion != AttackTermsVersion {
		return ConsentStale, c
	}
	return ConsentGranted, c
}

// RecordAttackConsent stores the acceptance of the current attack terms.
func RecordAttackConsent(saltPath, at string) error {
	p := AttackConsentPath(saltPath)
	b, err := json.Marshal(Consent{TermsVersion: AttackTermsVersion, AcceptedAt: at})
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
		return fmt.Errorf("creating consent directory: %w", err)
	}
	return os.WriteFile(p, b, 0o600)
}

// WithdrawAttackConsent removes the acceptance; withdrawing nothing is fine.
func WithdrawAttackConsent(saltPath string) error {
	if err := os.Remove(AttackConsentPath(saltPath)); err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("withdrawing attack consent: %w", err)
	}
	return nil
}

// AttackAllowlist is the complete set of fields a contributed run may carry. It
// mirrors evidence.RunReport's json tags; a test asserts they agree, so a field
// cannot be added to the shared type without being listed (and reviewed) here.
func AttackAllowlist() []AllowedField {
	return []AllowedField{
		{"schema_version", "the run-report wire version (1)"},
		{"fingerprint", "the intelligence candidate you say the run exercised"},
		{"exploitability", "the state the run reached: POTENTIAL..CONFIRMED"},
		{"kind", "how the run's evidence was established; its strength is derived"},
		{"deterministic", "a machine-checkable oracle decided the outcome"},
		{"reproduced", "the violation recurred under the determinism gate"},
		{"control_sound", "the benign control stayed clean, so the environment could tell obedience from noise"},
		{"samples", "determinism samples taken"},
		{"hits", "samples in which the violation recurred"},
		{"profile", "safety profile used: sandbox, staging or authorized-live"},
		{"trace_digest", "SHA-256 of the recorded trace; one-way"},
		{"tool", "the producing tool, nox"},
		{"version", "the nox build"},
		{"observed_at", "when the run happened"},
	}
}
