package intel

import (
	"errors"
	"fmt"
	"strings"
)

// Mode selects how much of what nox observed may leave the environment that
// observed it. The whole privacy contract hangs on this one switch, so it is a
// named type rather than a bare string: a value can only enter the system
// through ParseMode, which refuses anything it does not recognise.
type Mode string

// Contribution modes, from "nothing leaves" to "everything shareable leaves".
const (
	// ModeDisabled is the default and shares nothing. It is not merely the
	// absence of a setting: contribution in this mode is an error, so a caller
	// that forgot to configure the network finds out, rather than believing it
	// contributed.
	ModeDisabled Mode = "disabled"
	// ModeAnonymous contributes redacted observations with an opaque reporter
	// id. The id exists only so corroboration can count distinct reporters; it
	// is derived from a local salt and is not reversible to a workspace.
	ModeAnonymous Mode = "anonymous"
	// ModeOrgPrivate keeps observations inside the organization. Org-internal
	// coordinates (service, environment, owning team) are retained because they
	// are what makes an internal exposure actionable — but content is refused
	// here exactly as it is everywhere else.
	ModeOrgPrivate Mode = "org-private"
	// ModePublic contributes to the public intelligence network. It carries the
	// same redacted payload as ModeAnonymous; the difference is who may read it.
	ModePublic Mode = "public-intelligence"
)

// ErrContributionDisabled is returned when a contribution is attempted while
// the network is off. Returning an error rather than an empty result is
// deliberate: "nothing was contributed" and "contribution is disabled" must not
// look alike to a caller deciding whether to report success to a user.
var ErrContributionDisabled = errors.New("intel: contribution is disabled; no observation may leave this environment")

// ParseMode resolves a configuration string to a Mode.
//
// On error it returns ModeDisabled alongside the error, so a caller that
// mishandles the error still shares nothing. The empty string is the unset
// configuration and resolves to ModeDisabled without an error.
func ParseMode(s string) (Mode, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", string(ModeDisabled), "off", "none":
		return ModeDisabled, nil
	case string(ModeAnonymous):
		return ModeAnonymous, nil
	case string(ModeOrgPrivate), "org", "private":
		return ModeOrgPrivate, nil
	case string(ModePublic), "public":
		return ModePublic, nil
	default:
		return ModeDisabled, fmt.Errorf(
			"intel: unknown contribution mode %q (want one of: %s, %s, %s, %s)",
			s, ModeDisabled, ModeAnonymous, ModeOrgPrivate, ModePublic)
	}
}

// Valid reports whether m is a defined mode. An undefined mode is never treated
// as a permissive one.
func (m Mode) Valid() bool {
	switch m {
	case ModeDisabled, ModeAnonymous, ModeOrgPrivate, ModePublic:
		return true
	}
	return false
}

// SharesExternally reports whether observations in this mode cross the
// organization boundary. ModeOrgPrivate deliberately does not: its data stays
// on infrastructure the organization controls, which is why it may keep
// org-internal coordinates that the external modes drop.
func (m Mode) SharesExternally() bool {
	return m == ModeAnonymous || m == ModePublic
}

// Describe returns a one-line, user-facing reading of the mode. The wording is
// fixed here so every surface (CLI, config dump, MCP) makes the same promise.
func (m Mode) Describe() string {
	switch m {
	case ModeDisabled:
		return "contribution disabled; no observation leaves this environment"
	case ModeAnonymous:
		return "redacted observations shared under an opaque reporter id; no paths, content, or identities"
	case ModeOrgPrivate:
		return "redacted observations shared within this organization only; content is still refused"
	case ModePublic:
		return "redacted observations shared with the public intelligence network; no paths, content, or identities"
	default:
		return "unknown contribution mode; treated as disabled"
	}
}
