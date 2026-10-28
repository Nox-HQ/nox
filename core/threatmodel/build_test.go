package threatmodel

import (
	"strings"
	"testing"
)

// A route names the reader that found it; the statement must not call a
// Next.js, NestJS or Django route an Express one, nor a Django one Flask.
func TestRouteStatementNamesTheReaderThatFoundTheRoute(t *testing.T) {
	cases := []struct{ reader, file, want string }{
		{"Next.js", "app/api/x/route.ts", "route registration read by the Next.js reader"},
		{"Django", "api/urls.py", "route registration read by the Django reader"},
		{"FastAPI", "main.py", "route registration read by the FastAPI reader"},
		{"", "old.py", "(Python)"},
		{"", "old.js", "(JavaScript or TypeScript)"},
	}
	for _, c := range cases {
		if got := routeStatement(c.reader, c.file); !strings.Contains(got, c.want) {
			t.Errorf("routeStatement(%q, %q) = %q, want it to contain %q", c.reader, c.file, got, c.want)
		}
	}
}
