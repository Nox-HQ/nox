package ai

import "testing"

// TestAI006_ConstantMessageIsNotAPromptLeak covers AI-006 ("Prompt or LLM
// response logged without redaction", CWE-532) firing on a printf call whose
// only argument is a constant sentence containing the word "prompt":
//
//	fmt.Fprintf(os.Stderr, "this looks like CI, where nobody can approve a browser prompt.\n")
//
// Two halves of the pattern combine to produce it. `print` matches inside
// `Fprintf`, and the noun alternation then matches the word anywhere in the
// call — including inside a string literal. Nox's own CLI tripped it (#497),
// and the finding cannot be true: nothing dynamic is logged, so there is no
// prompt to leak.
//
// The `want: true` rows are the half that makes the suppression safe. A leak
// needs a value, and each shape below logs one — a bare identifier, a
// concatenation, an f-string hole, a template-literal hole, a printf argument —
// plus the call the filter cannot read to the end, which it must report rather
// than assume harmless. Suppressing any of those would report a clean scan of
// code that really does write prompts to the log, which is worse than the false
// positive being fixed.
func TestAI006_ConstantMessageIsNotAPromptLeak(t *testing.T) {
	cases := []struct {
		name string
		file string
		src  string
		want bool
	}{
		{
			name: "constant sentence about a browser prompt",
			file: "intel_login.go",
			src:  "package cli\n\nfunc run() int {\n\tfmt.Fprintf(os.Stderr, \"nox intel login: this looks like CI, where nobody can approve a browser prompt.\\n\")\n\treturn 2\n}\n",
			want: false,
		},
		{
			name: "constant usage line naming a subcommand",
			file: "completion_cmd.go",
			src:  "package cli\n\nfunc usage() {\n\tfmt.Fprintln(os.Stderr, \"Usage: nox completion <bash|zsh|fish|powershell>\")\n}\n",
			want: false,
		},
		{
			name: "constant status line about prompt-injection findings",
			file: "confirm_cmd.go",
			src:  "package cli\n\nfunc report() {\n\tfmt.Println(\"[confirm] no AI prompt-injection findings in findings.json — nothing to confirm\")\n}\n",
			want: false,
		},
		{
			// A long message wrapped with `+` puts the call's closing paren on a
			// later line, so reading only the matched line cannot see that the
			// continuation is constant too.
			name: "constant message wrapped across two lines",
			file: "intel_login.go",
			src:  "package cli\n\nfunc run() {\n\tfmt.Fprintf(os.Stderr, \"nox intel login: nobody can approve a browser prompt.\\n\"+\n\t\t\"Use a scoped token in NOX_INTEL_TOKEN instead.\\n\")\n}\n",
			want: false,
		},
		{
			name: "prompt passed as a bare identifier",
			file: "agent.go",
			src:  "package agent\n\nvar prompt string\n\nfunc emit() {\n\tfmt.Println(prompt)\n}\n",
			want: true,
		},
		{
			name: "completion passed as a bare identifier",
			file: "agent.go",
			src:  "package agent\n\nvar completion string\n\nfunc emit() {\n\tfmt.Println(completion)\n}\n",
			want: true,
		},
		{
			name: "prompt concatenated into the message",
			file: "app.py",
			src:  "logger.info(\"Prompt: \" + prompt)\n",
			want: true,
		},
		{
			name: "prompt interpolated into an f-string",
			file: "app.py",
			src:  "print(f\"Prompt: {prompt}\")\n",
			want: true,
		},
		{
			name: "prompt interpolated into a template literal",
			file: "app.js",
			src:  "console.log(`prompt: ${prompt}`)\n",
			want: true,
		},
		{
			name: "prompt passed as a printf argument",
			file: "agent.go",
			src:  "package agent\n\nfunc emit(userPrompt string) {\n\tfmt.Printf(\"prompt: %s\\n\", userPrompt)\n}\n",
			want: true,
		},
		{
			name: "response body logged through a writer",
			file: "agent.go",
			src:  "package agent\n\nfunc emit(w io.Writer, response Resp) {\n\tfmt.Fprintf(w, \"llm reply: %s\\n\", response.Content)\n}\n",
			want: true,
		},
		{
			// A close paren inside the message must not be mistaken for the end
			// of the call: mis-reading it truncates the search for the logged
			// value, and the leak below would be suppressed on a smiley.
			name: "prompt logged after a message containing a stray close paren",
			file: "agent.go",
			src:  "package agent\n\nvar prompt string\n\nfunc emit() {\n\tlog.Printf(\"prompt :) %s\\n\", prompt)\n}\n",
			want: true,
		},
		{
			// The value is the first argument and the constant text follows it,
			// so "is there code after the noun" alone would miss this one.
			name: "prompt logged ahead of a constant separator",
			file: "agent.go",
			src:  "package agent\n\nvar prompt string\n\nfunc emit() {\n\tfmt.Println(prompt, \"--- end of prompt ---\")\n}\n",
			want: true,
		},
		{
			name: "prompt logged as an argument on the next line",
			file: "agent.go",
			src:  "package agent\n\nfunc emit(userPrompt string) {\n\tfmt.Printf(\"prompt: %s\\n\",\n\t\tuserPrompt)\n}\n",
			want: true,
		},
		{
			// Source whose call never closes cannot be read, and a filter that
			// cannot read the call must not decide it is harmless. Reported, not
			// suppressed — the fail-safe direction for a security scanner.
			name: "unbalanced call is kept rather than judged",
			file: "broken.go",
			src:  "package cli\n\nfunc run() {\n\tfmt.Fprintf(os.Stderr, \"approve a browser prompt.\\n\"\n}\n",
			want: true,
		},
		{
			name: "response field logged directly",
			file: "app.js",
			src:  "console.log(response.content)\n",
			want: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got bool
			for _, f := range scanOneAI(t, tc.file, tc.src) {
				if f.RuleID == "AI-006" {
					got = true
				}
			}
			if got != tc.want {
				if tc.want {
					t.Fatalf("AI-006 stopped firing here — the constant-message filter must not "+
						"reach a call that logs a value, nor one it cannot read to the end:\n%s", tc.src)
				}
				t.Fatalf("AI-006 fired on a call whose arguments are all constant — nothing "+
					"dynamic is logged, so there is no prompt to leak:\n%s", tc.src)
			}
		})
	}
}
