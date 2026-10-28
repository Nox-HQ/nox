package ai

import (
	"regexp"
	"sort"
)

// Credential binding: which environment variable feeds the client that makes a
// model call.
//
// The inventory used to answer this by taking the first credential-looking
// environment variable anywhere in the file. In a file that also talks to a
// payment provider that is the wrong variable, and it is stated as fact: the
// measured case was gpt-4o attributed to STRIPE_SECRET (truncated, too, from
// STRIPE_SECRET_KEY) while the OpenAI client was built from OPENAI_API_KEY. A
// wrong credential name in an inventory sends a reviewer to rotate, scope or
// audit the wrong secret.
//
// The binding is now structural. The call is `recv.chat.completions.create(...)`
// (or `recv.Method(ctx, Request{...})`); recv was assigned from a constructor
// (`recv = new OpenAI({...})`, `recv := openai.NewClient(...)`); the constructor
// names the credential (`apiKey: process.env.X`, `api_key=os.environ["X"]`,
// `option.WithAPIKey(os.Getenv("X"))`, or the variable it was copied from one
// step earlier). Each link must resolve to exactly one variable. Anything that
// does not (no receiver, a client built from a config object or a helper, two
// constructions with different keys, the SDK reading its default variable
// implicitly) is reported as unknown, which is the honest answer: the field is
// omitted rather than guessed.

// envRefSrc matches a read of an environment variable; the name is whichever
// capture group is non-empty.
const envRefSrc = `(?:process\.env\.([A-Za-z_]\w*)` +
	`|process\.env\[\s*["']([A-Za-z_]\w*)["']\s*\]` +
	`|os\.getenv\s*\(\s*["']([A-Za-z_]\w*)["'][^)]*\)` +
	`|os\.environ\.get\s*\(\s*["']([A-Za-z_]\w*)["'][^)]*\)` +
	`|os\.environ\[\s*["']([A-Za-z_]\w*)["']\s*\]` +
	`|os\.Getenv\s*\(\s*"([A-Za-z_]\w*)"\s*\)` +
	`|System\.getenv\s*\(\s*"([A-Za-z_]\w*)"\s*\))`

var (
	envRefAtStart = regexp.MustCompile(`^\s*` + envRefSrc)
	// credKeyed finds `apiKey: <value>` / `api_key=<value>` style arguments.
	credKeyed = regexp.MustCompile(`(?i)(?:^|[^\w])(?:api_?key|auth_?token|access_?token|bearer_?token|secret_?key|token|secret|key)\s*[:=]\s*`)
	// credOption finds Go functional options such as option.WithAPIKey(...).
	credOption = regexp.MustCompile(`With(?:API|Auth)?(?:Key|Token)\s*\(`)
	identOnly  = regexp.MustCompile(`^\s*([A-Za-z_$][\w$]*)\s*(?:[,)}\n]|$)`)
	recvDotEnd = regexp.MustCompile(`([A-Za-z_$][\w$]*)\s*\.\s*$`)
	// recvGoCall finds the receiver of the call whose argument list holds the
	// request literal: `client.CreateChatCompletion(ctx, openai.Request{`.
	recvGoCall = regexp.MustCompile(`([A-Za-z_]\w*)\s*\.\s*[A-Za-z_]\w*\s*\(\s*(?:[^()]*?,\s*)?$`)
)

const (
	bindLookBehind = 200  // bytes before a call searched for its receiver
	bindMaxArgs    = 2000 // bytes of a constructor's arguments examined
)

// envRefName returns the variable named by an environment read, or "".
func envRefName(m []string) string {
	for _, g := range m[1:] {
		if g != "" {
			return g
		}
	}
	return ""
}

// credentialFor returns the environment variable that authenticates the client
// the model call at offset pos is made on, or "" when it cannot be established.
func credentialFor(content []byte, pos int) string {
	recv := receiverBefore(content, pos)
	if recv == "" {
		return ""
	}
	text := string(content)
	found := map[string]bool{}
	ambiguous := false
	record := func(name string) {
		if name == "" {
			ambiguous = true
			return
		}
		found[name] = true
	}

	args := clientConstructions(text, recv)
	for _, a := range args {
		record(credentialInArgs(text, a))
	}
	// Module-level configuration: `openai.api_key = os.getenv("X")`.
	attr := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(recv) + `\.(?:api_?key|apiKey)\s*=\s*`)
	for _, loc := range attr.FindAllStringIndex(text, -1) {
		record(credentialValue(text, text[loc[1]:]))
	}

	if ambiguous || len(found) != 1 {
		return ""
	}
	for name := range found {
		return name
	}
	return ""
}

// clientConstructions returns the argument text of every constructor call that
// assigns recv (`recv = new OpenAI({...})`, `recv := openai.NewClient(...)`).
// Credential and endpoint binding both read the client's own construction, so
// they cannot attribute one client's settings to another's calls.
func clientConstructions(text, recv string) (args []string) {
	ctor := regexp.MustCompile(`(?:^|[^\w$])` + regexp.QuoteMeta(recv) +
		`\s*(?::=|=)\s*(?:await\s+)?(?:new\s+)?[A-Za-z_$][\w$.]*\s*\(`)
	for _, loc := range ctor.FindAllStringIndex(text, -1) {
		args = append(args, balanced(text, loc[1]-1))
	}
	return args
}

// receiverBefore returns the identifier a model call is made on.
func receiverBefore(content []byte, pos int) string {
	start := pos - bindLookBehind
	if start < 0 {
		start = 0
	}
	before := string(content[start:pos])
	if m := recvDotEnd.FindStringSubmatch(before); m != nil {
		return m[1]
	}
	if m := recvGoCall.FindStringSubmatch(before); m != nil {
		return m[1]
	}
	return ""
}

// balanced returns the text between the bracket at open and its match, capped
// at bindMaxArgs. An unterminated bracket yields what was read.
func balanced(text string, open int) string {
	if open < 0 || open >= len(text) {
		return ""
	}
	depth := 0
	end := open + 1 + bindMaxArgs
	if end > len(text) {
		end = len(text)
	}
	for i := open; i < end; i++ {
		switch text[i] {
		case '(', '{', '[':
			depth++
		case ')', '}', ']':
			depth--
			if depth == 0 {
				return text[open+1 : i]
			}
		}
	}
	return text[open+1 : end]
}

// credentialInArgs finds the credential a constructor's arguments name, or ""
// when there is none or more than one distinct one.
func credentialInArgs(fullText, args string) string {
	names := map[string]bool{}
	add := func(n string) {
		if n != "" {
			names[n] = true
		}
	}
	for _, loc := range credKeyed.FindAllStringIndex(args, -1) {
		add(credentialValue(fullText, args[loc[1]:]))
	}
	for _, loc := range credOption.FindAllStringIndex(args, -1) {
		add(credentialValue(fullText, balanced(args, loc[1]-1)))
	}
	if len(names) == 0 {
		// `NewClient(os.Getenv("X"))`: a bare environment read as the first
		// argument is the key for the constructors that take one.
		if m := envRefAtStart.FindStringSubmatch(args); m != nil {
			add(envRefName(m))
		}
	}
	if len(names) != 1 {
		return ""
	}
	for n := range names {
		return n
	}
	return ""
}

// credentialValue resolves the start of a value to an environment variable:
// directly (`process.env.X`) or through one variable assigned from one.
func credentialValue(fullText, value string) string {
	if m := envRefAtStart.FindStringSubmatch(value); m != nil {
		return envRefName(m)
	}
	m := identOnly.FindStringSubmatch(value)
	if m == nil {
		return ""
	}
	assign := regexp.MustCompile(`(?:^|[^\w$.])` + regexp.QuoteMeta(m[1]) + `\s*(?::=|=)\s*`)
	var names []string
	for _, loc := range assign.FindAllStringIndex(fullText, -1) {
		if em := envRefAtStart.FindStringSubmatch(fullText[loc[1]:]); em != nil {
			names = append(names, envRefName(em))
		}
	}
	sort.Strings(names)
	names = dedupSorted(names)
	if len(names) != 1 {
		return ""
	}
	return names[0]
}

func dedupSorted(in []string) []string {
	out := in[:0]
	for i, s := range in {
		if i == 0 || s != in[i-1] {
			out = append(out, s)
		}
	}
	return out
}
