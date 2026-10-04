package refs

import "math/rand"

// GitHub is the union of the two published GitHub token shapes. The claiming
// rules do not distinguish them, so a candidate must be judged against both:
// judging a classic token against the stateless reference alone reports a
// "prefix" violation that is a fact about the split, not about nox.
var GitHub = union("github-token", "x is a GitHub token in either published shape", &GitHubClassic, &GitHubStateless)

// Modelled is every format with an independent reference.
var Modelled = []*Format{&GitHub, &AWSAccessKeyID, &TwilioAPIKeySID, &SNSTopicARN, &Age, &PyPI, &JWT, &PEMPrivateKey}

func union(name, prop string, fs ...*Format) Format {
	u := Format{Name: name, Proposition: prop, Claims: fs[0].Claims, Hosts: fs[0].Hosts}
	for _, f := range fs {
		u.Sources = append(u.Sources, f.Sources...)
		u.Limits = append(u.Limits, f.Limits...)
	}
	u.Check = func(s string) string {
		first := ""
		for _, f := range fs {
			v := f.Check(s)
			if v == "" {
				return ""
			}
			if first == "" {
				first = v
			}
		}
		return first
	}
	u.Valid = func(r *rand.Rand) []Named {
		var out []Named
		for _, f := range fs {
			out = append(out, f.Valid(r)...)
		}
		return out
	}
	u.Mutate = func(r *rand.Rand, v string) []Named {
		if GitHubClassic.Check(v) == "" {
			return GitHubClassic.Mutate(r, v)
		}
		return GitHubStateless.Mutate(r, v)
	}
	return u
}
