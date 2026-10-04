package refs

import "math/rand"

// Format is one independently specified credential format.
//
// Check is the reference predicate. It returns "" when its argument IS an
// instance of the format, and otherwise the name of the first constraint the
// argument violates. The name is what makes a witness adjudicable: "checksum"
// and "length" are different disagreements even when both are FPs.
//
// Check judges its whole argument. It does not search inside it: tokenisation
// is part of what is being tested, so a valid token glued to a letter is not
// a valid token.
type Format struct {
	Name string
	// Proposition is the security claim the reference models, which is not
	// always "matches the format": an unsigned JWT matches the JWT format and
	// is not a credential.
	Proposition string
	Sources     []Source
	// Claims are the nox rule IDs whose description claims this format. Read
	// off the rule descriptions in the built rule dump, not off patterns.
	Claims []string
	// Hosts are the file shapes a candidate is embedded in.
	Hosts []Host
	Check func(s string) (violation string)
	// Valid returns reference-valid instances, each named for the variant of
	// the format it exercises.
	Valid func(r *rand.Rand) []Named
	// Mutate returns inputs one constraint away from a valid instance.
	Mutate func(r *rand.Rand, valid string) []Named
	// Limits are the model's stated assumptions.
	Limits []string
}

type Source struct{ URL, Establishes string }

type Named struct{ Name, S string }

// Host embeds a candidate into a file. Ext is the file extension; Wrap
// returns the file content and the byte offset of the candidate in it.
type Host struct {
	Name string
	Ext  string
	Wrap func(candidate string) (content string, offset int)
}

func linePrefix(name, ext, pre, post string) Host {
	return Host{Name: name, Ext: ext, Wrap: func(c string) (string, int) {
		return pre + c + post, len(pre)
	}}
}

var (
	HostPyQuoted = linePrefix("py-quoted", "py", `value = "`, "\"\n")
	HostYAMLBare = linePrefix("yaml-bare", "yaml", "value: ", "\n")
	HostRaw      = linePrefix("raw-file", "pem", "", "")
)

// HostMarkdown puts the candidate in prose, outside any assignment: the
// context in which a generic "high-entropy value in an assignment" rule
// cannot stand in for the format rule.
var HostMarkdown = linePrefix("md-inline", "md", "The key we rotated was `", "`.\n")

// Single-line hosts every token format is tried in. Each format adds the
// host its issuer actually writes.
var tokenHosts = []Host{HostPyQuoted, HostYAMLBare, HostMarkdown}

func randFrom(r *rand.Rand, alphabet string, n int) string {
	b := make([]byte, n)
	for i := range b {
		b[i] = alphabet[r.Intn(len(alphabet))]
	}
	return string(b)
}

// Generic one-constraint-away mutants that apply to every single-line
// token format: tokenisation (glued neighbours) and truncation/extension.
func tokenMutants(r *rand.Rand, v string, bodyAlphabet string) []Named {
	return []Named{
		{"glued-left-alnum", "x" + v},
		{"glued-right-alnum", v + string(bodyAlphabet[r.Intn(len(bodyAlphabet))])},
		{"truncated-1", v[:len(v)-1]},
		{"extended-1", v + string(bodyAlphabet[r.Intn(len(bodyAlphabet))])},
	}
}
