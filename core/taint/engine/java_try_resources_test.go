package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A try-with-resources header declares locals: `try (ObjectInputStream in =
// new ObjectInputStream(...)) { in.readObject(); }`. The header was skipped as
// a control keyword, so the resource was never bound and nothing read from
// it reached a sink.
func TestJavaTryWithResourcesBindsTheResource(t *testing.T) {
	head := "class A {\n  void h(HttpServletRequest request) throws Exception {\n" +
		"    byte[] bytes = java.util.Base64.getDecoder().decode(request.getParameter(\"s\"));\n"
	tail := "  }\n}\n"
	cases := []struct {
		name, body string
		want       bool
	}{
		{"one resource", "    try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n      Object o = in.readObject();\n    }\n", true},
		{"header across two lines", "    try (java.io.ObjectInputStream in =\n             new java.io.ObjectInputStream(new java.io.ByteArrayInputStream(bytes))) {\n      Object o = in.readObject();\n    }\n", true},
		{"var resource", "    try (var in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n      Object o = in.readObject();\n    }\n", true},
		{"second resource built from the first", "    try (var bin = new ByteArrayInputStream(bytes); ObjectInputStream in = new ObjectInputStream(bin)) {\n      Object o = in.readObject();\n    }\n", true},
		{"after a closing brace", "    if (bytes == null) {\n      return;\n    } try (ObjectInputStream in = new ObjectInputStream(new ByteArrayInputStream(bytes))) {\n      in.readObject();\n    }\n", true},
		{"a resource from a fixed stream", "    try (ObjectInputStream in = new ObjectInputStream(getClass().getResourceAsStream(\"/a.ser\"))) {\n      Object o = in.readObject();\n    }\n", false},
		{"a try without resources", "    try {\n      Object o = new Object();\n    } catch (Exception e) {\n    }\n", false},
	}
	for _, c := range cases {
		got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+c.body+tail), "TAINT-005")
		if got != c.want {
			t.Errorf("%s: TAINT-005 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
