package engine

import (
	"reflect"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// TestJSFunctionNames pins the names JavaScript units carry. A modifier was
// trimmed as a bare prefix, so `getUser(id) {` was "User" and `settings() {`
// "tings", and a function named get or set had no name at all, because the
// shared keyword list holds Swift's accessors.
func TestJSFunctionNames(t *testing.T) {
	src := "class A {\n  getUser(id) {\n    load(id);\n  }\n  async settings() {\n    x();\n  }\n  static get(u) {\n    y();\n  }\n}\n" +
		"export function get(u) {\n  return z(u);\n}\nexport async function setup() {\n  w();\n}\n"
	var got []string
	for _, u := range ExtractUnits("a.js", lexctx.LangJavaScript, []byte(src)) {
		if u.FuncName != "" {
			got = append(got, u.FuncName)
		}
	}
	want := []string{"getUser", "settings", "get", "get", "setup"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("unit names = %v, want %v", got, want)
	}
}
