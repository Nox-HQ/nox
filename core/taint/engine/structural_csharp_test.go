package engine

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// analyzeCSharpFile runs the full same-file pipeline (extraction +
// interprocedural AnalyzeFile) over C# source, mirroring how taintflow drives
// the engine.
func analyzeCSharpFile(t *testing.T, src string) []string {
	t.Helper()
	eng := NewStructuralEngine(nil)
	units := ExtractUnits("t.cs", lexctx.LangCSharp, []byte(src))
	flows := eng.AnalyzeFile(units)
	return ruleIDs(flows)
}

func TestStructuralCSharpTruePositives(t *testing.T) {
	tests := []struct {
		name   string
		src    string
		wantID string
	}{
		{
			name: "command injection via Process.Start",
			src: `public class C {
    void M(HttpRequest Request) {
        var name = Request.QueryString["report"];
        Process.Start("cmd.exe", "/c gen " + name);
    }
}`,
			wantID: "TAINT-002",
		},
		{
			name: "sql injection via SqlCommand concat",
			src: `public class C {
    void M(HttpRequest Request) {
        var id = Request.QueryString["id"];
        var cmd = new SqlCommand("SELECT * FROM t WHERE id = '" + id + "'");
        cmd.ExecuteReader();
    }
}`,
			wantID: "TAINT-001",
		},
		{
			name: "path traversal via File.ReadAllText",
			src: `public class C {
    void M(HttpRequest Request) {
        var file = Request.QueryString["file"];
        var data = File.ReadAllText(file);
    }
}`,
			wantID: "TAINT-004",
		},
		{
			name: "ssrf via WebClient.DownloadString",
			src: `public class C {
    void M(HttpRequest Request) {
        var target = Request.QueryString["url"];
        var body = new WebClient().DownloadString(target);
    }
}`,
			wantID: "TAINT-006",
		},
		{
			name: "unsafe deserialization via BinaryFormatter",
			src: `public class C {
    void M(HttpRequest Request) {
        var blob = Request.Form["state"];
        var fmt = new BinaryFormatter();
        var obj = fmt.Deserialize(blob);
    }
}`,
			wantID: "TAINT-005",
		},
		{
			name: "xss via Response.Write",
			src: `public class C {
    void M(HttpRequest Request, HttpResponse Response) {
        var q = Request.QueryString["q"];
        Response.Write("Hello " + q);
    }
}`,
			wantID: "TAINT-003",
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeCSharpFile(t, tt.src)
			if !containsStr(ids, tt.wantID) {
				t.Errorf("flows = %v, want to include %s", ids, tt.wantID)
			}
		})
	}
}

func TestStructuralCSharpCleanNoFlow(t *testing.T) {
	tests := []struct {
		name string
		src  string
	}{
		{
			name: "parameterized SqlCommand is safe",
			src: `public class C {
    void M(HttpRequest Request) {
        var id = Request.QueryString["id"];
        var cmd = new SqlCommand("SELECT * FROM t WHERE id = @id");
        cmd.Parameters.AddWithValue("@id", id);
        cmd.ExecuteReader();
    }
}`,
		},
		{
			name: "HtmlEncode defuses XSS",
			src: `public class C {
    void M(HttpRequest Request, HttpResponse Response) {
        var q = Request.QueryString["q"];
        var safe = HttpUtility.HtmlEncode(q);
        Response.Write("Hello " + safe);
    }
}`,
		},
		{
			name: "int.Parse defuses path traversal",
			src: `public class C {
    void M(HttpRequest Request) {
        var raw = Request.QueryString["page"];
        var n = int.Parse(raw);
        var data = File.ReadAllText("/data/" + n);
    }
}`,
		},
		{
			name: "no source: constant path",
			src: `public class C {
    void M() {
        var data = File.ReadAllText("/etc/config");
    }
}`,
		},
	}
	for _, tt := range tests {
		tt := tt
		t.Run(tt.name, func(t *testing.T) {
			ids := analyzeCSharpFile(t, tt.src)
			if len(ids) != 0 {
				t.Errorf("clean sample fired %v, want no flows", ids)
			}
		})
	}
}
