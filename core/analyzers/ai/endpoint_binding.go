package ai

import (
	"regexp"
)

// Endpoint binding: the non-default URL the client a model call is made on was
// built with.
//
// detectEndpoint took the first base_url / baseURL / azure_endpoint anywhere in
// the file and gave it to every model call in that file, the same shape as the
// credential bug (a wrong environment variable attributed to a model). A file
// that sends gpt-4o to api.openai.com and a different request to a self-hosted
// gateway recorded the gateway against both, which tells a reviewer that
// prompts go somewhere they do not, or that they stay somewhere they do not.
//
// The endpoint is now read from the construction of the client the call is made
// on, by the same link credentialFor follows, and reported only when every
// construction of that client agrees. Where the link cannot be made (no
// receiver, a client built by a helper, two constructions that differ, an
// endpoint that is not a literal) the answer is "unknown": the field is
// omitted, which the inventory already reads as "default or not established".

var (
	// endpointKeyed finds the keyword arguments and object keys that carry an
	// endpoint, with a quoted literal as the value.
	endpointKeyed = regexp.MustCompile(`(?i)(?:^|[^\w])(?:base_?url|azure_?endpoint|api_?base|endpoint)\s*[:=]\s*["']([^"']+)["']`)
	// endpointOption finds Go functional options such as option.WithBaseURL("...").
	endpointOption = regexp.MustCompile(`With(?:Base|Endpoint)URL\s*\(\s*"([^"]+)"`)
	// bedrockRegion is the region of a bedrock-runtime client, the only
	// endpoint information that client carries.
	bedrockRegion = regexp.MustCompile(`bedrock-runtime[^)]*region_name\s*=\s*["']([^"']+)["']`)
)

// endpointFor returns the endpoint of the client the model call at offset pos
// is made on, or "" when the client uses the provider default or when it cannot
// be established.
func endpointFor(content []byte, pos int) string {
	recv := receiverBefore(content, pos)
	if recv == "" {
		return ""
	}
	text := string(content)
	seen := map[string]bool{}
	for _, args := range clientConstructions(text, recv) {
		seen[endpointInArgs(args)] = true
	}
	// Module-level configuration: `openai.base_url = "https://..."`.
	attr := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(recv) + `\.(?:base_?url|api_?base|baseURL)\s*=\s*["']([^"']+)["']`)
	for _, m := range attr.FindAllStringSubmatch(text, -1) {
		seen[m[1]] = true
	}
	if len(seen) != 1 {
		return ""
	}
	for e := range seen {
		return e
	}
	return ""
}

// endpointInArgs returns the one literal endpoint a constructor's arguments
// set, "" when there is none, and a sentinel-free "" also when there are several
// that disagree (the caller treats a disagreement between constructions as
// unknown, and one construction that disagrees with itself is no different).
func endpointInArgs(args string) string {
	found := map[string]bool{}
	for _, m := range endpointKeyed.FindAllStringSubmatch(args, -1) {
		found[m[1]] = true
	}
	for _, m := range endpointOption.FindAllStringSubmatch(args, -1) {
		found[m[1]] = true
	}
	for _, m := range bedrockRegion.FindAllStringSubmatch(args, -1) {
		found[m[1]] = true
	}
	if len(found) != 1 {
		return ""
	}
	for e := range found {
		return e
	}
	return ""
}
