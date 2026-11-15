package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// ssrfLines returns the lines TAINT-006 reports for src.
func ssrfLines(t *testing.T, file string, lang lexctx.Lang, src string) []int {
	t.Helper()
	var out []int
	for _, f := range NewStructuralEngine(nil).AnalyzeFile(ExtractUnits(file, lang, []byte(src))) {
		if f.Sink.RuleID == "TAINT-006" {
			out = append(out, f.SinkLine)
		}
	}
	return out
}

// Each case is one file. guarded says whether the host is pinned before the
// sink; every unguarded case is a counterexample a guard recognizer that is
// too generous would clear.
var hostGuardCases = []struct {
	name    string
	file    string
	lang    lexctx.Lang
	src     string
	guarded bool
}{
	// Nox-HQ/nox#1096, reduced from nox-hq.dev's scripts/sync-plugins.mjs.
	{"js braced guard exits", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
if (u.protocol !== 'https:' || u.hostname !== 'raw.githubusercontent.com') {
  console.error('bad host');
  process.exit(2);
}
const res = await fetch(u.href);
`, true},
	{"js unbraced guard throws", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
if ('api.example.com' !== u.hostname) throw new Error('host');
await fetch(u.href);
`, true},
	{"js no guard", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
await fetch(u.href);
`, false},
	{"js guard logs and continues", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
if (u.hostname !== 'raw.githubusercontent.com') {
  console.warn('unexpected host');
}
await fetch(u.href);
`, false},
	{"js host compared to a variable", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
const want = process.env.WANT;
if (u.hostname !== want) process.exit(2);
await fetch(u.href);
`, false},
	{"js rejects only the good host", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
if (u.hostname === 'raw.githubusercontent.com') process.exit(2);
await fetch(u.href);
`, false},
	{"js protocol only", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
if (u.protocol !== 'https:') process.exit(2);
await fetch(u.href);
`, false},
	{"js sink before the guard", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
await fetch(u.href);
if (u.hostname !== 'raw.githubusercontent.com') process.exit(2);
`, false},
	{"js a different value is fetched", "a.mjs", lexctx.LangJavaScript, `const u = new URL(process.env.TARGET_URL);
const v = process.env.OTHER_URL;
if (u.hostname !== 'raw.githubusercontent.com') process.exit(2);
await fetch(v);
`, false},

	{"python guard exits on the parsed url", "a.py", lexctx.LangPython, `import os, sys, urllib.request
from urllib.parse import urlparse
u = os.environ["TARGET_URL"]
p = urlparse(u)
if p.scheme != "https" or p.hostname not in ("a.example.com", "b.example.com"):
    sys.exit(2)
urllib.request.urlopen(u)
`, true},
	{"python no guard", "a.py", lexctx.LangPython, `import os, urllib.request
u = os.environ["TARGET_URL"]
urllib.request.urlopen(u)
`, false},
	{"python guard prints and continues", "a.py", lexctx.LangPython, `import os, urllib.request
from urllib.parse import urlparse
u = os.environ["TARGET_URL"]
p = urlparse(u)
if p.hostname != "a.example.com":
    print("unexpected")
urllib.request.urlopen(u)
`, false},

	{"shell case pins the host", "a.sh", lexctx.LangShell, `#!/bin/sh
url=$1
case "$url" in
  https://raw.githubusercontent.com/*) ;;
  *) echo "bad host" >&2; exit 2 ;;
esac
curl -fsSL "$url"
`, true},
	{"shell no guard", "a.sh", lexctx.LangShell, `#!/bin/sh
url=$1
curl -fsSL "$url"
`, false},
	{"shell host prefix without a slash", "a.sh", lexctx.LangShell, `#!/bin/sh
url=$1
case "$url" in
  https://good.example*) ;;
  *) exit 2 ;;
esac
curl -fsSL "$url"
`, false},
	{"shell default arm does not exit", "a.sh", lexctx.LangShell, `#!/bin/sh
url=$1
case "$url" in
  https://raw.githubusercontent.com/*) ;;
  *) echo "unexpected host" >&2 ;;
esac
curl -fsSL "$url"
`, false},
}

func TestAHostPinningGuardClearsSSRF(t *testing.T) {
	for _, c := range hostGuardCases {
		got := ssrfLines(t, c.file, c.lang, c.src)
		switch {
		case c.guarded && len(got) > 0:
			t.Errorf("%s: TAINT-006 at %v after a guard that pins the host and leaves", c.name, got)
		case !c.guarded && len(got) == 0:
			t.Errorf("%s: TAINT-006 not reported; nothing here pins the host before the sink", c.name)
		}
	}
}

// The guard clears SSRF only: the same value reaching a command is still
// command injection.
func TestAHostGuardDoesNotClearOtherClasses(t *testing.T) {
	src := `#!/bin/sh
url=$1
case "$url" in
  https://raw.githubusercontent.com/*) ;;
  *) exit 2 ;;
esac
eval "$url"
`
	var classes []string
	for _, f := range NewStructuralEngine(nil).AnalyzeFile(ExtractUnits("a.sh", lexctx.LangShell, []byte(src))) {
		classes = append(classes, f.Sink.RuleID)
	}
	if len(classes) == 0 {
		t.Errorf("eval of a host-checked URL reported nothing; the guard must clear SSRF only")
	}
}
