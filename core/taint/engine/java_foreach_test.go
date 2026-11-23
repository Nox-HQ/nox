package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// An enhanced for header binds its element from the collection, and the calls
// the collection expression makes are calls of the method.
func TestJavaForEachHeader(t *testing.T) {
	src := `class C {
	List<String> search(String q, int start) {
		List<String> out = new ArrayList<>();
		for (String cn : directory.find(q)) {
			out.add(cn);
		}
		for (int i = q.isEmpty() ? start : 0; i < q.length(); i++) {
			out.add(q);
		}
		return out;
	}
}`
	units := ExtractUnits("C.java", lexctx.LangJava, []byte(src))
	var found bool
	for _, u := range units {
		for _, st := range u.Stmts {
			if st.Line == 7 && st.Assigns != "" {
				t.Errorf("a classic for header bound %q", st.Assigns)
			}
			if st.Line != 4 {
				continue
			}
			found = true
			if st.Assigns != "cn" || !slices.Contains(st.Calls, "directory.find") || !slices.Contains(st.Reads, "q") || !st.Conditional {
				t.Errorf("for-each header = %+v, want cn = directory.find(q), conditional", st)
			}
		}
	}
	if !found {
		t.Fatal("the for-each header produced no statement")
	}
}

// The element of a request-derived collection is tainted inside the loop.
func TestJavaForEachCarriesTaint(t *testing.T) {
	flows := analyzeJavaFile(t, `class H {
	void run(HttpServletRequest request) {
		for (String name : request.getParameterValues("f")) {
			Runtime.getRuntime().exec("convert " + name);
		}
	}
}`)
	if len(flows) != 1 || flows[0].Sink.RuleID != "TAINT-002" || flows[0].SinkLine != 4 {
		t.Fatalf("want one TAINT-002 at line 4, got %+v", flows)
	}
}
