package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeScalaFile runs the full same-file pipeline (extraction +
// interprocedural AnalyzeFile) over Scala source, mirroring how taintflow drives
// the engine.
func analyzeScalaFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.scala", lexctx.LangScala, []byte(src))
	flows := eng.AnalyzeFile(units)
	return ruleIDs(flows)
}

func TestStructuralScalaTruePositives(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		wantID string
	}{
		{
			name: "command injection via Process",
			src: `class C {
  def run(request: Request): Unit = {
    val cmd = request.getQueryString("cmd")
    Process("sh -c " + cmd).run()
  }
}`,
			wantID: "TAINT-002",
		},
		{
			name: "command injection via postfix .! process operator",
			src: `class C {
  def run(request: Request): Unit = {
    val cmd = request.getQueryString("cmd")
    val out = s"sh -c $cmd".!
  }
}`,
			wantID: "TAINT-002",
		},
		{
			name: "sql injection via Statement.executeQuery concat",
			src: `class C {
  def lookup(request: Request, stmt: Statement): Unit = {
    val id = request.getQueryString("id")
    stmt.executeQuery("SELECT * FROM users WHERE id = '" + id + "'")
  }
}`,
			wantID: "TAINT-001",
		},
		{
			name: "path traversal via Source.fromFile",
			src: `class C {
  def read(request: Request): String = {
    val name = request.getQueryString("file")
    Source.fromFile("/srv/" + name).mkString
  }
}`,
			wantID: "TAINT-004",
		},
		{
			name: "ssrf via URL openStream",
			src: `class C {
  def fetch(request: Request): Unit = {
    val target = request.getQueryString("url")
    val in = new URL(target).openStream()
  }
}`,
			wantID: "TAINT-006",
		},
		{
			name: "unsafe deserialization via ObjectInputStream over tainted bytes",
			src: `class C {
  def load(request: Request): Unit = {
    val blob = request.body
    val ois = new ObjectInputStream(blob)
    val obj = ois.readObject()
  }
}`,
			wantID: "TAINT-005",
		},
		{
			name: "xss via Twirl Html",
			src: `class C {
  def greet(request: Request): Html = {
    val name = request.getQueryString("name")
    Html("<h1>Hello " + name + "</h1>")
  }
}`,
			wantID: "TAINT-003",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeScalaFile(t, tt.src)
			if !containsStr(ids, tt.wantID) {
				t.Errorf("flows = %v, want to include %s", ids, tt.wantID)
			}
		})
	}
}

func TestStructuralScalaCleanNoFlow(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "prepared statement is safe",
			src: `class C {
  def lookup(request: Request, conn: Connection): Unit = {
    val id = request.getQueryString("id")
    val stmt = conn.prepareStatement("SELECT * FROM users WHERE id = ?")
    stmt.setString(1, id)
    stmt.executeQuery()
  }
}`,
		},
		{
			name: "toInt coercion defuses path traversal",
			src: `class C {
  def read(request: Request): String = {
    val raw = request.getQueryString("page")
    val n = raw.toInt
    Source.fromFile("/data/" + n).mkString
  }
}`,
		},
		{
			name: "escapeHtml defuses XSS",
			src: `class C {
  def greet(request: Request): Html = {
    val name = request.getQueryString("name")
    val safe = escapeHtml(name)
    Html("<h1>Hello " + safe + "</h1>")
  }
}`,
		},
		{
			name: "no source: constant path",
			src: `class C {
  def read(): String = {
    Source.fromFile("/etc/config").mkString
  }
}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeScalaFile(t, tt.src)
			if len(ids) != 0 {
				t.Errorf("clean sample fired %v, want no flows", ids)
			}
		})
	}
}
