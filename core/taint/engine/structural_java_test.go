package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
	"github.com/nox-hq/nox/core/taint"
)

// analyzeJavaFile runs the full same-file pipeline (extraction + interprocedural
// AnalyzeFile) over Java source, mirroring how taintflow drives the engine.
func analyzeJavaFile(t *testing.T, src string) []taint.Flow {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("T.java", lexctx.LangJava, []byte(src))
	return eng.AnalyzeFile(units)
}

func TestStructuralJavaTruePositives(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		wantID string
	}{
		{
			name: "command injection via Runtime.exec",
			src: `class H {
	void run(HttpServletRequest request) {
		String name = request.getParameter("report");
		Runtime.getRuntime().exec("generate-report " + name);
	}
}`,
			wantID: "TAINT-002",
		},
		{
			name: "command injection via ProcessBuilder",
			src: `class H {
	void run(HttpServletRequest request) {
		String cmd = request.getParameter("cmd");
		ProcessBuilder pb = new ProcessBuilder("sh", "-c", cmd);
		pb.start();
	}
}`,
			wantID: "TAINT-002",
		},
		{
			name: "sql injection via Statement.executeQuery concat",
			src: `class S {
	void lookup(HttpServletRequest request, Statement stmt) {
		String id = request.getParameter("id");
		stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'");
	}
}`,
			wantID: "TAINT-001",
		},
		{
			name: "path traversal via new File",
			src: `class F {
	void serve(HttpServletRequest request) {
		String path = request.getParameter("file");
		File f = new File("/srv/" + path);
	}
}`,
			wantID: "TAINT-004",
		},
		{
			name: "path traversal via Files.readAllBytes",
			src: `class F {
	void serve(HttpServletRequest request) {
		String path = request.getParameter("file");
		byte[] data = Files.readAllBytes(Paths.get(path));
	}
}`,
			wantID: "TAINT-004",
		},
		{
			name: "ssrf via new URL openStream",
			src: `class P {
	void fetch(HttpServletRequest request) {
		String target = request.getParameter("url");
		new URL(target).openStream();
	}
}`,
			wantID: "TAINT-006",
		},
		{
			name: "unsafe deserialization via readObject",
			src: `class D {
	void load(HttpServletRequest request) {
		ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
		Object o = ois.readObject();
	}
}`,
			wantID: "TAINT-005",
		},
		{
			name: "code injection via ScriptEngine.eval",
			src: `class E {
	void evaluate(HttpServletRequest request, ScriptEngine engine) {
		String script = request.getParameter("expr");
		engine.eval(script);
	}
}`,
			wantID: "TAINT-005",
		},
		{
			name: "xss via response writer println",
			src: `class X {
	void render(HttpServletRequest request, HttpServletResponse resp) {
		String msg = request.getParameter("msg");
		resp.getWriter().println("<div>" + msg + "</div>");
	}
}`,
			wantID: "TAINT-003",
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeJavaFile(t, tt.src)
			if !hasRule(flows, tt.wantID) {
				t.Errorf("want rule %s to fire; got flows %v", tt.wantID, ruleIDs(flows))
			}
		})
	}
}

func TestStructuralJavaCleanSamples(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "parameterized prepared statement",
			src: `class S {
	void lookup(HttpServletRequest request, Connection conn) {
		String id = request.getParameter("id");
		PreparedStatement ps = conn.prepareStatement("SELECT * FROM users WHERE id = ?");
		ps.setString(1, id);
		ps.executeQuery();
	}
}`,
		},
		{
			name: "numeric coercion sanitizes command",
			src: `class H {
	void run(HttpServletRequest request) {
		String raw = request.getParameter("n");
		String n = Integer.parseInt(raw) + "";
		Runtime.getRuntime().exec("job " + n);
	}
}`,
		},
		{
			name: "html-escaped output",
			src: `class X {
	void render(HttpServletRequest request, HttpServletResponse resp) {
		String raw = request.getParameter("msg");
		String msg = StringEscapeUtils.escapeHtml4(raw);
		resp.getWriter().println(msg);
	}
}`,
		},
		{
			name: "constant command, no taint",
			src: `class H {
	void run() {
		Runtime.getRuntime().exec("ls -la");
	}
}`,
		},
	}

	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			flows := analyzeJavaFile(t, tt.src)
			if len(flows) != 0 {
				t.Errorf("clean sample should produce no flows; got %v", ruleIDs(flows))
			}
		})
	}
}
