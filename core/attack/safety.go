package attack

import (
	"fmt"
	"time"
)

// Profile is a safety envelope. It decides, structurally, whether a run may send
// network traffic at all and whether the caller must have authorized it. The
// point of a profile is that safety is a property of the run's configuration, not
// a flag an operator is trusted to remember: Run consults it before firing.
type Profile string

// Profiles, from most to least restrictive.
const (
	// ProfileSafe forbids all network traffic. Only SimTarget (which sends
	// nothing) may be used with it; the run models what it would do without
	// doing it. This is the default any caller should reach for first.
	ProfileSafe Profile = "safe"
	// ProfileSandbox permits traffic against a disposable, isolated target the
	// operator stood up for testing.
	ProfileSandbox Profile = "sandbox"
	// ProfileStaging permits traffic against a non-production environment.
	ProfileStaging Profile = "staging"
	// ProfileAuthorizedLive permits traffic against a live system. It exists so
	// the intent to attack production is explicit and auditable, never implicit.
	ProfileAuthorizedLive Profile = "authorized-live"
)

// ParseProfile parses s into a Profile, returning an error for an unknown value
// so a typo can never silently widen what a run is allowed to do.
func ParseProfile(s string) (Profile, error) {
	switch Profile(s) {
	case ProfileSafe, ProfileSandbox, ProfileStaging, ProfileAuthorizedLive:
		return Profile(s), nil
	default:
		return "", fmt.Errorf("attack: unknown profile %q (want safe, sandbox, staging, or authorized-live)", s)
	}
}

// AllowsNetwork reports whether the profile permits any network traffic. Only
// ProfileSafe returns false; it is the single profile under which a run is
// physically incapable of reaching a real target.
func (p Profile) AllowsNetwork() bool { return p != ProfileSafe }

// RequiresAuthorization reports whether the profile demands explicit caller
// authorization before a run may proceed. Every profile that allows network
// traffic requires it — sending an attack payload is never a default.
func (p Profile) RequiresAuthorization() bool { return p != ProfileSafe }

// Describe returns a one-line, user-facing reading of the profile's guarantees.
func (p Profile) Describe() string {
	switch p {
	case ProfileSafe:
		return "no network traffic; intent is recorded but nothing is sent"
	case ProfileSandbox:
		return "traffic permitted against a disposable, isolated sandbox target"
	case ProfileStaging:
		return "traffic permitted against a non-production staging target"
	case ProfileAuthorizedLive:
		return "traffic permitted against a live target; requires explicit authorization"
	default:
		return "unknown profile"
	}
}

// rank orders profiles by how much they permit, so a scenario can declare a
// minimum profile and a run below it is skipped rather than silently downgraded.
func profileRank(p Profile) int {
	switch p {
	case ProfileSafe:
		return 0
	case ProfileSandbox:
		return 1
	case ProfileStaging:
		return 2
	case ProfileAuthorizedLive:
		return 3
	default:
		return -1
	}
}

// Budget caps the resources a single run may consume. A run stops the moment any
// limit trips (see Run and Result.BudgetStop); a cut-short run is reported as
// INCONCLUSIVE, never as PREVENTED, because it was interrupted rather than
// defended against.
type Budget struct {
	// Attempts caps the total number of probes fired.
	Attempts int `json:"attempts"`
	// NetworkRequests caps probes that actually leave the process (SimTarget
	// probes do not count).
	NetworkRequests int `json:"network_requests"`
	// ModelCalls caps probes that reach a model-backed target.
	ModelCalls int `json:"model_calls"`
	// ToolInvocations caps observed tool invocations across the run.
	ToolInvocations int `json:"tool_invocations"`
	// Duration caps wall-clock time. The engine itself reads no clock; a caller
	// that wants this enforced supplies RunConfig.Clock. Without one it is a
	// declared ceiling that a networked caller can wire to a real timer.
	Duration time.Duration `json:"duration"`
}

// DefaultBudget returns a conservative budget suitable for a small V1 corpus.
func DefaultBudget() Budget {
	return Budget{
		Attempts:        200,
		NetworkRequests: 500,
		ModelCalls:      500,
		ToolInvocations: 100,
		Duration:        5 * time.Minute,
	}
}

// Spend is the running tally a Budget is measured against.
type Spend struct {
	// Attempts is the number of probes fired.
	Attempts int `json:"attempts"`
	// NetworkRequests is the number of probes that left the process.
	NetworkRequests int `json:"network_requests"`
	// ModelCalls is the number of probes that reached a model-backed target.
	ModelCalls int `json:"model_calls"`
	// ToolInvocations is the number of observed tool invocations.
	ToolInvocations int `json:"tool_invocations"`
	// Elapsed is caller-supplied wall-clock time, or zero in the pure engine.
	Elapsed time.Duration `json:"elapsed"`
}

// Exhausted reports whether spend has reached any of the budget's limits, and
// which limit tripped first. A zero limit means "unbounded" for that dimension,
// so a caller can cap only the dimensions it cares about. The check order is
// fixed so the reported limit is deterministic.
func (b Budget) Exhausted(s Spend) (tripped bool, limit string) {
	switch {
	case b.Attempts > 0 && s.Attempts >= b.Attempts:
		return true, "attempts"
	case b.NetworkRequests > 0 && s.NetworkRequests >= b.NetworkRequests:
		return true, "network_requests"
	case b.ModelCalls > 0 && s.ModelCalls >= b.ModelCalls:
		return true, "model_calls"
	case b.ToolInvocations > 0 && s.ToolInvocations >= b.ToolInvocations:
		return true, "tool_invocations"
	case b.Duration > 0 && s.Elapsed >= b.Duration:
		return true, "duration"
	}
	return false, ""
}
