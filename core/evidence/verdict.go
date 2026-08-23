package evidence

// RunOutcome summarises what one attack run observed about a single exploit
// hypothesis. It is the raw input to DeriveExploitability; keeping the
// derivation here means core/attack and core/intel cannot disagree about what
// "CONFIRMED" means.
type RunOutcome struct {
	// HypothesisConstructed is true once nox has a credible attack path, whether
	// or not anything was executed.
	HypothesisConstructed bool `json:"hypothesis_constructed"`
	// Executed is true if at least one attempt actually ran against a target.
	// A simulation-only (safe-profile) run leaves this false.
	Executed bool `json:"executed"`
	// Violated is true only when an oracle observed the security invariant being
	// violated. Set it from a deterministic oracle wherever one exists.
	Violated bool `json:"violated"`
	// Reproduced is true when the violation recurred under the determinism gate.
	// A violation that will not reproduce is real but unreliable, and nox says so
	// rather than pretending it is either certain or absent.
	Reproduced bool `json:"reproduced"`
	// DefenseObserved is true when the target actively refused or blocked the
	// attempt (a guardrail fired, authorization denied). It is what separates
	// "a defense stopped this" from "nothing happened".
	DefenseObserved bool `json:"defense_observed"`
	// BudgetExhausted is true when the run stopped on a budget rather than on a
	// conclusion. Such a run can never be PREVENTED — it was cut short, not
	// defended against.
	BudgetExhausted bool `json:"budget_exhausted"`
	// ControlSound is false when the benign control tripped a signal, meaning the
	// environment cannot distinguish obedience from noise. Nothing may be
	// confirmed from an unsound environment.
	ControlSound bool `json:"control_sound"`
	// TargetErrors counts attempts that failed to reach the target at all.
	TargetErrors int `json:"target_errors"`
}

// DeriveExploitability maps a run outcome and its evidence ledger onto the
// lifecycle state.
//
// The ordering is deliberate and each branch encodes a rule nox must not break:
//
//   - CONFIRMED requires an observed violation, a sound control environment, AND
//     a deterministic claim in the ledger. A semantic judgment that an attack
//     "probably worked" cannot confirm anything (§4.3, §14).
//   - A violation that is observed but unreproducible, or observed in an unsound
//     environment, is INCONCLUSIVE — never quietly upgraded and never discarded.
//   - PREVENTED requires the run to have completed AND a defense to have been
//     observed. A run cut short by a budget, or one that merely saw nothing, is
//     INCONCLUSIVE: "we did not exploit it" is not "it is defended" (§25, false
//     confidence).
//   - Without execution, the state is PLAUSIBLE if a hypothesis exists and
//     POTENTIAL otherwise.
func DeriveExploitability(o RunOutcome, l *Ledger) Exploitability {
	if !o.Executed {
		if o.HypothesisConstructed {
			return Plausible
		}
		return Potential
	}

	if o.Violated {
		switch {
		case !o.ControlSound:
			// The environment could not tell obedience from echo, so the
			// "violation" proves nothing.
			return Inconclusive
		case !o.Reproduced:
			return Inconclusive
		case l == nil || !l.HasDeterministic():
			// Something judged this a violation, but nothing machine-checkable
			// backs it. That is a lead, not a proof.
			return Inconclusive
		default:
			return Confirmed
		}
	}

	if o.BudgetExhausted || o.TargetErrors > 0 || !o.ControlSound {
		return Inconclusive
	}
	if o.DefenseObserved {
		return Prevented
	}
	return Inconclusive
}

// Describe returns a one-line, user-facing reading of a state that never
// overstates it. §25 of the exploit-validation PRD is explicit that nox must
// report "attack not reproduced" or "prevented under tested strategies" and
// never simply "safe" — this is where that wording is fixed, so every surface
// (CLI, report, MCP) says the same careful thing.
func Describe(e Exploitability) string {
	switch e {
	case Potential:
		return "static evidence only; no attack path constructed"
	case Plausible:
		return "credible attack path constructed; not executed"
	case Prevented:
		return "not exploited under the strategies tested; a defense was observed"
	case Inconclusive:
		return "executed, but the evidence was insufficient to decide"
	case Confirmed:
		return "a security invariant was observed being violated, and it reproduced"
	default:
		return "unknown exploitability state"
	}
}
