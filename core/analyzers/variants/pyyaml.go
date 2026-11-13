package variants

import (
	"regexp"
)

// lineRefuters carry the part of a signature its exclude pattern cannot: a
// fact about the line that needs the rest of the file to establish. Each
// returns true when the matched line is the fixed form after all.
var lineRefuters = map[string]struct {
	check  func(content, line string) bool
	reason string
}{
	"VARIANT-002": {
		pyyamlLoaderBindsSafe,
		"the Loader passed is a name this file binds only to yaml's safe " +
			"loaders (SafeLoader, CSafeLoader, BaseLoader, CBaseLoader), so the " +
			"call cannot construct arbitrary objects",
	},
}

// loaderArgName captures a Loader keyword argument given as a bare name:
// `Loader=UniqueKeyLoader)`, `Loader=loader,`. An attribute (`self.loader`) or
// a call is not resolved and stays a finding.
var loaderArgName = regexp.MustCompile(`\bLoader\s*=\s*([A-Za-z_][A-Za-z0-9_]*)\s*[,)]`)

// loaderToken finds every PyYAML loader class a definition names.
var loaderToken = regexp.MustCompile(`\bC?(?:Safe|Base|Full|Unsafe)?Loader\b`)

var safeLoaders = map[string]bool{
	"SafeLoader": true, "CSafeLoader": true, "BaseLoader": true, "CBaseLoader": true,
}

// pyyamlLoaderBindsSafe reports whether the line's `Loader=<name>` names
// something this file defines only from safe loaders: a class whose bases are
// all safe loaders, or an assignment whose right-hand side names only safe
// loaders (`getattr(yaml, 'CSafeLoader', yaml.SafeLoader)`).
//
// Every definition of the name must qualify, and at least one must exist: a
// name rebound to an unsafe loader anywhere, or imported from elsewhere, is
// not established safe and the finding stands (#928).
func pyyamlLoaderBindsSafe(content, line string) bool {
	m := loaderArgName.FindStringSubmatch(line)
	if m == nil {
		return false
	}
	name := regexp.QuoteMeta(m[1])
	defs := regexp.MustCompile(`(?m)^[ \t]*(?:class[ \t]+`+name+`[ \t]*\(([^)]*)\)|`+
		name+`[ \t]*(?::[^=\n]+)?=[ \t]*([^=\n].*)$)`).FindAllStringSubmatch(content, -1)
	if len(defs) == 0 {
		return false
	}
	for _, d := range defs {
		rhs := d[1] + d[2]
		tokens := loaderToken.FindAllString(rhs, -1)
		if len(tokens) == 0 {
			return false
		}
		for _, tok := range tokens {
			if !safeLoaders[tok] {
				return false
			}
		}
	}
	return true
}
