package iac

import (
	"path/filepath"
	"strings"

	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// A filename is a discovery hint. It is not evidence that a rule applies.
//
// The Serverless Framework family scoped itself with
//
//	{"serverless.yml", "serverless.yaml", "serverless.ts", "*.yml", "*.yaml"}
//
// where the last two entries make the first three meaningless: every rule in
// the family applied to every YAML file in any repository. Measured 2026-09-12
// on MacPaw/OpenAI@0.5.1, a Swift package, IAC-254 ("Serverless environment
// variable with hardcoded secret", CRITICAL) fired 268 times on openapi.yaml
// against Ruby documentation samples reading
//
//	openai = OpenAI::Client.new(api_key: "My API Key")
//
// and told the reader to use ${ssm:/path/to/secret} in a file that has no such
// concept.
//
// Three independent things had to line up, and removing any one of them would
// have hidden rather than fixed it: the *.yaml catch-all made every YAML file
// eligible; the rule's keywords gate at FILE level, so one "environment"
// anywhere in a 2.8MB specification admitted the whole file; and the pattern
// matches any `api_key:` assignment. Narrowing the glob to serverless*.yml
// would have left the family able to fire on serverless-named files that are
// not manifests, and left the other IaC families with the same shape untouched.
//
// So applicability is decided by the document, once, for the family: a
// Serverless rule fires only where the document IS a Serverless manifest.

// serverlessFamilyTag marks a rule as belonging to the Serverless Framework
// family. Keying on the tag rather than on an ID list is what makes this
// structural: a rule added to the family tomorrow inherits the gate without
// anyone remembering to add it anywhere.
const serverlessFamilyTag = "serverless"

// isServerlessManifest reports whether content is a Serverless Framework
// manifest.
//
// The Framework requires both `service` and `provider`; a document carrying
// neither is not one, whatever it is called. The check is deliberately shallow
// — it reads top-level keys, not the whole schema — because its job is to
// separate "this is a serverless.yml" from "this is an OpenAPI spec", not to
// validate a configuration.
//
// It errs toward applying the rules: a manifest that somehow omits `provider`
// still counts on the strength of `service`, because a missed finding costs
// more than a false one and the two keys together are what the format
// guarantees, not what every file in the wild contains.
func isServerlessManifest(path string, content []byte) bool {
	// A TypeScript config expresses the same keys as object properties rather
	// than as YAML, so the top-level-column rule does not apply to it.
	topLevelOnly := true
	if ext := strings.ToLower(filepath.Ext(path)); ext == ".ts" || ext == ".js" {
		topLevelOnly = false
	}

	var service, provider bool
	for _, line := range strings.Split(string(content), "\n") {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if topLevelOnly && line != trimmed {
			// Indented: a nested key, not a document-level declaration. This is
			// what keeps `provider:` inside some unrelated structure from
			// making an OpenAPI spec look like a manifest.
			continue
		}
		switch {
		case strings.HasPrefix(trimmed, "service:"), strings.HasPrefix(trimmed, "service :"):
			service = true
		case strings.HasPrefix(trimmed, "provider:"), strings.HasPrefix(trimmed, "provider :"):
			provider = true
		}
		if service && provider {
			return true
		}
	}
	return service
}

// dropRulesOutsideTheirDocumentKind removes findings from a rule family whose
// document is not of that family's kind.
//
// Like every other refiner here it is handed a recorder rather than dropping
// silently: a filter that removes findings and the reason for removing them in
// the same statement produces a result indistinguishable from having had
// nothing to remove.
func dropRulesOutsideTheirDocumentKind(path string, in []findings.Finding, content []byte, set *rules.RuleSet, drop refuteFunc) []findings.Finding {
	if len(in) == 0 || set == nil {
		return in
	}
	// Computed once per file, and only when a family rule actually matched.
	var checked, serverless bool

	kept := in[:0]
	for _, f := range in {
		rule, ok := set.ByID(f.RuleID)
		if !ok || !hasTag(rule, serverlessFamilyTag) {
			kept = append(kept, f)
			continue
		}
		if !checked {
			serverless = isServerlessManifest(path, content)
			checked = true
		}
		if !serverless {
			drop(f, "this rule describes a Serverless Framework manifest, and this "+
				"document declares neither `service` nor `provider`, so it is not one. "+
				"The file name is a hint about what to parse, not evidence that the "+
				"rule applies")
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// hasTag reports whether a rule carries the given tag.
func hasTag(r *rules.Rule, tag string) bool {
	for _, t := range r.Tags {
		if t == tag {
			return true
		}
	}
	return false
}
