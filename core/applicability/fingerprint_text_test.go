package applicability

import (
	"testing"

	"github.com/nox-hq/nox/core/capability"
)

// Every sentence below is what nox 1.65.0 put in a dependency finding's
// message, and so what every dependency fingerprint recorded in a baseline, a
// waiver or a VEX statement since was computed over. A failure here is not a
// wording regression: it means dependency fingerprints moved.
//
// The reason in brackets comes from capability.State.Describe, which is why
// each state has a row: rewording a state there moves fingerprints too.
func TestFingerprintTextIsFrozen(t *testing.T) {
	tests := []struct {
		name string
		v    Verdict
		want string
	}{
		{
			"version matched, link set not asked",
			Verdict{Reached: AffectedVersion, Outcome: Undetermined, StoppedAt: SymbolUsed, Because: capability.Unsupported},
			`established as far as "affected_version"; symbol_used was not established (unsupported — this analysis cannot apply here)`,
		},
		{
			"linked, call graph unsupported",
			Verdict{Reached: SymbolUsed, Outcome: Undetermined, StoppedAt: CallReachable, Because: capability.Unsupported},
			`established as far as "symbol_used"; call_reachable was not established (unsupported — this analysis cannot apply here)`,
		},
		{
			"not evaluated",
			Verdict{Reached: Present, Outcome: Undetermined, StoppedAt: AffectedVersion, Because: capability.NotEvaluated},
			`established as far as "present"; affected_version was not established (not evaluated — nothing asked this question)`,
		},
		{
			"timed out",
			Verdict{Reached: SymbolUsed, Outcome: Undetermined, StoppedAt: CallReachable, Because: capability.TimedOut},
			`established as far as "symbol_used"; call_reachable was not established (timed out — the analysis was cut short, not completed)`,
		},
		{
			"unknown",
			Verdict{Reached: SymbolUsed, Outcome: Undetermined, StoppedAt: CallReachable, Because: capability.Unknown},
			`established as far as "symbol_used"; call_reachable was not established (evaluated, and could not determine an answer)`,
		},
		{
			"negative",
			Verdict{Reached: SymbolUsed, Outcome: Undetermined, StoppedAt: CallReachable, Because: capability.Negative},
			`established as far as "symbol_used"; call_reachable was not established (evaluated — the condition does not hold)`,
		},
		{
			"positive",
			Verdict{Reached: CallReachable, Outcome: Undetermined, StoppedAt: AttackerReachable, Because: capability.Positive},
			`established as far as "call_reachable"; attacker_reachable was not established (evaluated — the condition holds)`,
		},
		{
			"nothing stopped it",
			Verdict{Reached: AttackerReachable, Outcome: Undetermined},
			`established as far as "attacker_reachable"`,
		},
		{
			"not linked",
			Verdict{Reached: AffectedVersion, Outcome: NotImpacting, StoppedAt: SymbolUsed},
			`present, but not currently impacting this application: the affected package is not linked by this build`,
		},
		{
			"no call path",
			Verdict{Reached: SymbolUsed, Outcome: NotImpacting, StoppedAt: CallReachable},
			`present, but not currently impacting this application: no call path reaches the affected code`,
		},
		{
			"not attacker reachable",
			Verdict{Reached: CallReachable, Outcome: NotImpacting, StoppedAt: AttackerReachable},
			`present, but not currently impacting this application: the affected code is not reachable from attacker-controlled input`,
		},
		{
			"outside the range",
			Verdict{Reached: Present, Outcome: NotImpacting, StoppedAt: AffectedVersion},
			`present, but not currently impacting this application: the resolved version is outside the advisory's affected range`,
		},
		{
			"refuted at the bottom",
			Verdict{Outcome: NotImpacting, StoppedAt: Present},
			`present, but not currently impacting this application: an applicability requirement was established not to hold`,
		},
		{
			"call path",
			Verdict{Reached: CallReachable, Outcome: Impacting, Path: []string{"main.main", "pkg.Parse"}},
			`code in this build calls into the affected package, reached through 2 call(s) from an entry point. That a path exists is not that an attacker can take it — "attacker_reachable" was not established.`,
		},
		{
			"linked and impacting",
			Verdict{Reached: SymbolUsed, Outcome: Impacting},
			`the affected package is linked by this build, reached through 0 call(s) from an entry point. That a path exists is not that an attacker can take it — "attacker_reachable" was not established.`,
		},
		{
			"attacker reachable",
			Verdict{Reached: AttackerReachable, Outcome: Impacting, Path: []string{"a"}},
			`an attacker can cause the affected code to run, reached through 1 call(s) from an entry point. That a path exists is not that an attacker can take it — "attacker_reachable" was not established.`,
		},
		{
			"impacting below the link set",
			Verdict{Reached: AffectedVersion, Outcome: Impacting},
			`"affected_version" holds, reached through 0 call(s) from an entry point. That a path exists is not that an attacker can take it — "attacker_reachable" was not established.`,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.v.FingerprintText(); got != tc.want {
				t.Errorf("FingerprintText() =\n  %s\nwant\n  %s", got, tc.want)
			}
		})
	}
}
