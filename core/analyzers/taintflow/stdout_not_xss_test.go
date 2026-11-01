package taintflow

import (
	"fmt"
	"slices"
	"testing"
)

// Printing to the server's console is not output to a browser. The JVM XSS
// sinks are keyed by method name (println, print, write), so
// System.out.println(request.getParameter("t")) and Kotlin's bare println(t)
// -- which IS stdout -- were reported as cross-site scripting. A writer that
// reaches the response keeps the sink.
func TestConsoleOutputIsNotXSS(t *testing.T) {
	const java = `public class A extends HttpServlet {
  protected void doGet(HttpServletRequest request, HttpServletResponse response) throws IOException {
    String t = request.getParameter("t");
    %s
  }
}
`
	const kotlin = `fun h(request: HttpServletRequest, response: HttpServletResponse) {
    val t = request.getParameter("t")
    %s
}
`
	cases := []struct {
		name, file, tmpl, line string
		fires                  bool
	}{
		{"java System.out.println", "A.java", java, `System.out.println(t);`, false},
		{"java System.err.print", "A.java", java, `System.err.print(t);`, false},
		{"java response writer println", "A.java", java, `response.getWriter().println(t);`, true},
		{"java response writer local", "A.java", java, "PrintWriter out = response.getWriter();\n    out.println(t);", true},
		{"java response writer write", "A.java", java, `response.getWriter().write(t);`, true},
		{"kotlin bare println", "A.kt", kotlin, `println(t)`, false},
		{"kotlin System.out.println", "A.kt", kotlin, `System.out.println(t)`, false},
		{"kotlin response writer println", "A.kt", kotlin, `response.writer.println(t)`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := fmt.Sprintf(c.tmpl, c.line)
			ids := scan(t, writeArtifact(t, t.TempDir(), c.file, src))
			if got := slices.Contains(ids, "TAINT-003"); got != c.fires {
				t.Errorf("TAINT-003 fired = %v, want %v (findings %v):\n%s", got, c.fires, ids, src)
			}
		})
	}
}
