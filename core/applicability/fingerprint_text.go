package applicability

import "fmt"

// FingerprintText is the sentence a dependency finding's fingerprint is
// computed over. It is not for display: Describe is.
//
// A dependency finding has no matched text to hash, so its fingerprint has
// always been the hash of its message, and this sentence is the second half of
// that message as nox 1.65.0 printed it. A baseline entry, a waiver and a VEX
// statement are all keyed on the result. Rewording what a person reads is a
// change to Describe; a change here moves every dependency fingerprint, and a
// project that baselined its dependency findings gets all of them back as new.
//
// So this text is frozen, rung identifiers and all, and the test beside it
// pins every sentence it can produce. If one of them has to change, that is a
// fingerprint migration (findings.AliasFingerprints is how the old identity
// keeps matching), not a wording fix.
func (v Verdict) FingerprintText() string {
	switch v.Outcome {
	case NotImpacting:
		return fmt.Sprintf("present, but not currently impacting this application: %s", frozenRefuted(v.StoppedAt))
	case Impacting:
		return fmt.Sprintf("%s, reached through %d call(s) from an entry point. "+
			"That a path exists is not that an attacker can take it — "+
			"%q was not established.",
			frozenReached(v.Reached), len(v.Path), AttackerReachable)
	default:
		if v.StoppedAt == "" {
			return fmt.Sprintf("established as far as %q", v.Reached)
		}
		return fmt.Sprintf("established as far as %q; %s was not established (%s)",
			v.Reached, v.StoppedAt, v.Because.Describe())
	}
}

func frozenReached(r Rung) string {
	switch r {
	case SymbolUsed:
		return "the affected package is linked by this build"
	case CallReachable:
		return "code in this build calls into the affected package"
	case AttackerReachable:
		return "an attacker can cause the affected code to run"
	default:
		return fmt.Sprintf("%q holds", r)
	}
}

func frozenRefuted(r Rung) string {
	switch r {
	case SymbolUsed:
		return "the affected package is not linked by this build"
	case CallReachable:
		return "no call path reaches the affected code"
	case AttackerReachable:
		return "the affected code is not reachable from attacker-controlled input"
	case AffectedVersion:
		return "the resolved version is outside the advisory's affected range"
	default:
		return "an applicability requirement was established not to hold"
	}
}
