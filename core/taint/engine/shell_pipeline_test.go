package engine

import (
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A positional / CGI source used DIRECTLY as a sink argument, with no
// intermediate assignment. `eval "$@"` and `bash -c "$*"` are the ordinary
// wrapper-script idiom; both were invisible because positional parameters were
// only recognized on the RHS of an assignment.
func TestShellInlineSourceInSinkArg(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"sh -c $1", "sh -c \"run $1\"\n", []string{"TAINT-002"}},
		{"eval $@", "eval \"$@\"\n", []string{"TAINT-005"}},
		{"curl QUERY_STRING", "curl \"$QUERY_STRING\"\n", []string{"TAINT-006"}},
		{"inside function", "run() {\n  bash -c \"$1\"\n}\nrun \"$2\"\n", []string{"TAINT-002"}},
		// Single quotes make the expansion inert: the literal text `$1` is run.
		{"single-quoted is inert", "sh -c 'run $1'\n", nil},
		// A sanitizer wrapping the source at the call site still clears it.
		{"basename clears traversal", "source \"$(basename \"$1\")\"\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.sh", lexctx.LangShell, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

// A tainted value that reaches a sink THROUGH A PIPELINE: `xargs` turns stdin
// into arguments of the command it invokes, and a bare `sh`/`bash` executes
// stdin as a script. The recognizer used to see only a command's own argument
// words, so the piped value was invisible.
func TestShellPipelineFeedsSink(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"xargs curl", "fetch_all() {\n  local urls=\"$1\"\n  echo \"$urls\" | xargs curl -fsSL\n}\nfetch_all \"$1\"\n", []string{"TAINT-006"}},
		{"xargs -I sh -c with $1", "process_all() {\n  find . -name '*.txt' -print0 | xargs -0 -I{} sh -c \"process {} $1\"\n}\nprocess_all \"$2\"\n", []string{"TAINT-002"}},
		{"echo | sh", "x=\"$1\"\necho \"$x\" | sh\n", []string{"TAINT-002"}},
		{"echo | bash -s", "x=\"$1\"\nprintf '%s\\n' \"$x\" | bash -s\n", []string{"TAINT-002"}},
		{"through a filter", "u=\"$1\"\necho \"$u\" | grep -v x | xargs -n1 curl\n", []string{"TAINT-006"}},
		{"inline source upstream", "echo \"$1\" | xargs wget\n", []string{"TAINT-006"}},
		// Negatives: the piped value reaches a non-sink, or the executed string is
		// fixed and stdin is mere data to it.
		{"xargs non-sink", "u=\"$1\"\necho \"$u\" | xargs echo\n", nil},
		{"sh -c fixed script", "u=\"$1\"\necho \"$u\" | sh -c 'cat'\n", nil},
		{"nothing tainted upstream", "ls | xargs curl\n", nil},
		{"or is not a pipe", "x=\"$1\"\ntest -n \"$x\" || sh -c 'echo none'\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.sh", lexctx.LangShell, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

// A privilege / environment wrapper in front of the real command is transparent:
// the sink is the command it runs.
func TestShellWrapperPrefixIsTransparent(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"sudo sh -c", "cmd=\"$1\"\nsudo sh -c \"$cmd\"\n", []string{"TAINT-002"}},
		{"sudo -u user bash -c", "cmd=\"$1\"\nsudo -u deploy bash -c \"$cmd\"\n", []string{"TAINT-002"}},
		{"env VAR= curl", "url=\"$1\"\nenv HTTPS_PROXY=x curl \"$url\"\n", []string{"TAINT-006"}},
		{"nohup wget", "url=\"$1\"\nnohup wget \"$url\" &\n", []string{"TAINT-006"}},
		{"timeout N curl", "url=\"$1\"\ntimeout 30 curl \"$url\"\n", []string{"TAINT-006"}},
		{"sudo of a non-sink", "f=\"$1\"\nsudo chown root \"$f\"\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.sh", lexctx.LangShell, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

// A loop header that reads is a read: `while read -r line; do` binds `line`
// to untrusted stdin, and a sink in the body is reached. The header used to be
// skipped as structural scaffolding, which lost the variable.
func TestShellWhileReadHeaderBindsVariable(t *testing.T) {
	cases := []struct {
		name string
		src  string
		want []string
	}{
		{"pipe into while read eval", "cat \"$f\" | while read -r line; do\n  eval \"$line\"\ndone\n", []string{"TAINT-005"}},
		{"IFS prefix", "while IFS= read -r line; do\n  bash -c \"$line\"\ndone < \"$cfg\"\n", []string{"TAINT-002"}},
		{"body does not sink", "while read -r line; do\n  echo \"$line\"\ndone\n", nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := analyzeRuleIDs(t, "t.sh", lexctx.LangShell, tc.src)
			if !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("rules = %v, want %v", got, tc.want)
			}
		})
	}
}

// A trailing comment is not an argument list: `sh # runs stdin` is a bare sh.
func TestShellTrailingCommentIsNotArguments(t *testing.T) {
	src := "x=\"$1\"\necho \"$x\" | sh # executes what it reads\n"
	if got := analyzeRuleIDs(t, "t.sh", lexctx.LangShell, src); !reflect.DeepEqual(got, []string{"TAINT-002"}) {
		t.Fatalf("rules = %v, want [TAINT-002]", got)
	}
}
