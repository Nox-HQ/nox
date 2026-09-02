package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestTimerSink_FunctionLiteralIsNotCode: setTimeout compiles its first
// argument only when it is a string. A callback body that reads argv is the
// ordinary form and must not be reported as code injection; a string built
// from argv still must.
func TestTimerSink_FunctionLiteralIsNotCode(t *testing.T) {
	tests := []struct {
		name string
		src  string
		want bool
	}{
		{"function callback", `var args = process.argv.slice(2);
setTimeout(function() {
  if (args.length === 1 && args[0] === '--help') {
    console.log('x');
  }
}, 0);
`, false},
		{"async arrow callback", `var args = process.argv.slice(2);
setInterval(async () => { await run(args); }, 100);
`, false},
		{"bare-param arrow callback", `var args = process.argv.slice(2);
setTimeout(x => run(args, x), 0);
`, false},
		{"string built from argv", `var args = process.argv.slice(2);
setTimeout("run(" + args[0] + ")", 10);
`, true},
		{"tainted variable as code", `var code = process.argv[2];
setTimeout(code, 10);
`, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := hasRule(analyze(t, lexctx.LangJavaScript, tt.src), "TAINT-005")
			if got != tt.want {
				t.Fatalf("TAINT-005 fired=%v, want %v", got, tt.want)
			}
		})
	}
}
