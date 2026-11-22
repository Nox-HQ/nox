package appconfig

import (
	"strconv"
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Windowed matching must find exactly what whole-file matching finds. Each
// source holds a match whose start is above its literal, or a literal
// repeated on one long line.
func TestWindowedMatchesWholeFile(t *testing.T) {
	long := strings.Repeat("x=none;", 2000)
	for _, c := range []struct {
		name, path string
		lang       lexctx.Lang
		src        string
	}{
		{"header split across lines", "a.js", lexctx.LangJavaScript, "res.setHeader(\n  'Access-Control-Allow-Origin',\n  '*');\n"},
		{"algorithms split", "a.py", lexctx.LangPython, "jwt.decode(t, k, algorithms=[\n    'none'])\n"},
		{"ResponseCookie chain", "C.java", lexctx.LangJava, "var c = ResponseCookie.from(\"session\", s)\n    .path(\"/\")\n    .secure(true)\n    .httpOnly(false)\n    .build();\n"},
		{"jjwt chain", "J.java", lexctx.LangJava, "Jwts.parser()\n    .setSigningKey(k)\n    .parse(t);\n"},
		{"secret fallback split", "settings.py", lexctx.LangPython, "SECRET_KEY = os.environ.get(\n    \"DJANGO_SECRET_KEY\",\n    \"dev-insecure\"\n)\n"},
		{"minified line", "b.js", lexctx.LangJavaScript, long + "app.use(cors());res.cookie('auth_token',t);" + long + "\n"},
	} {
		key := func() map[string]bool {
			m := map[string]bool{}
			for _, f := range ScanFile(c.path, c.lang, []byte(c.src)) {
				m[f.RuleID+":"+strconv.Itoa(f.Location.StartLine)] = true
			}
			return m
		}
		wholeAll = true
		whole := key()
		wholeAll = false
		windowed := key()
		if len(whole) == 0 {
			t.Errorf("%s: nothing found; the case guards nothing", c.name)
		}
		for k := range whole {
			if !windowed[k] {
				t.Errorf("%s: %s found whole-file, lost when windowed", c.name, k)
			}
		}
		for k := range windowed {
			if !whole[k] {
				t.Errorf("%s: %s found only when windowed", c.name, k)
			}
		}
	}
}
