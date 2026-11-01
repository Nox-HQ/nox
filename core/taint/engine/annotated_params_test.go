package engine

import (
	"reflect"
	"testing"
)

func TestLeadingAnnotations(t *testing.T) {
	cases := []struct {
		slot, rest string
		names      []string
	}{
		{`@RequestParam String host`, "String host", []string{"RequestParam"}},
		{`@RequestParam(value = "h", required = false) final String host`, "final String host", []string{"RequestParam"}},
		{`@org.springframework.web.bind.annotation.PathVariable("id") Long id`, "Long id", []string{"PathVariable"}},
		{`@Valid @RequestBody Order order`, "Order order", []string{"Valid", "RequestBody"}},
		{`String host`, "String host", nil},
	}
	for _, c := range cases {
		names, rest := leadingAnnotations(c.slot)
		if rest != c.rest || !reflect.DeepEqual(names, c.names) {
			t.Errorf("leadingAnnotations(%q) = %v, %q; want %v, %q", c.slot, names, rest, c.names, c.rest)
		}
	}
}

func TestJavaRequestBound(t *testing.T) {
	got := javaRequestBound(`@GetMapping("/u/{id}") public String u(@PathVariable("id") String id, @RequestHeader("X-T") String tok, @Valid Form f, Model m) {`)
	want := map[string]string{"id": requestBoundQuery, "tok": requestBoundHeader}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("javaRequestBound = %v, want %v", got, want)
	}
}

// An annotation on a Kotlin parameter left the name as `@RequestParam host`,
// which is not an identifier, so the parameter was dropped from the unit and
// from every interprocedural summary through it.
func TestParseKotlinParamsDropsAnnotations(t *testing.T) {
	got := parseKotlinParams(`@RequestParam host: String, @PathVariable("id") id: Long, n: Int = 0`)
	if want := []string{"host", "id", "n"}; !reflect.DeepEqual(got, want) {
		t.Errorf("parseKotlinParams = %v, want %v", got, want)
	}
	if got := kotlinRequestBound(`fun ping(@RequestParam host: String, n: Int): String {`); !reflect.DeepEqual(got, map[string]string{"host": requestBoundQuery}) {
		t.Errorf("kotlinRequestBound = %v", got)
	}
}
