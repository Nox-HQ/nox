package plugin

import "strings"

// Plugin references arrive from untrusted places — a nox:// URI, a
// model-initiated MCP tool call, a CLI argument — and flow into registry
// resolution and the on-disk plugin store. These validators are the allowlist
// that keeps a path-traversal or injection payload out of that path.
//
// They live here, in the package that owns install, because three entry points
// need the SAME ceiling: the MCP plugin_install tool, the nox:// URI handler,
// and `nox plugin install`. They used to be copy-pasted in server/ and cli/
// (and the direct CLI install path enforced neither), so the guard could drift
// between surfaces or be skipped entirely. One definition, called everywhere,
// is the only way a security boundary stays a boundary.

const (
	maxPluginNameLen        = 200
	maxVersionConstraintLen = 50
)

// IsSafeName reports whether a plugin name is safe to resolve and install. It
// rejects empty or overlong names, any ".." (path traversal), a leading
// dot/dash/slash, and any character outside [A-Za-z0-9/._-].
func IsSafeName(s string) bool {
	if s == "" || len(s) > maxPluginNameLen {
		return false
	}
	if strings.Contains(s, "..") {
		return false
	}
	if s[0] == '.' || s[0] == '-' || s[0] == '/' {
		return false
	}
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r >= '0' && r <= '9':
		case r == '/' || r == '-' || r == '_' || r == '.':
		default:
			return false
		}
	}
	return true
}

// IsSafeVersionConstraint reports whether a version constraint is safe. It
// allows only the characters a semver constraint needs — digits, letters, and
// `. - + > = ^ ~` — and caps the length.
func IsSafeVersionConstraint(s string) bool {
	if s == "" || len(s) > maxVersionConstraintLen {
		return false
	}
	for _, r := range s {
		switch {
		case r >= '0' && r <= '9':
		case r >= 'a' && r <= 'z':
		case r >= 'A' && r <= 'Z':
		case r == '.' || r == '-' || r == '+' || r == '>' || r == '=' || r == '^' || r == '~':
		default:
			return false
		}
	}
	return true
}
