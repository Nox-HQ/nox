package engine

import "testing"

// TestDottedAssignRoot pins which assignment targets bind their receiver. Only a
// pure dotted chain of bare identifiers does: a subscripted or call-bearing
// target has no single object to attribute the taint to, and misattributing one
// would taint an unrelated name.
func TestDottedAssignRoot(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want string
		ok   bool
	}{
		{"task.arguments", "task", true},
		{"req.followRedirects", "req", true},
		{"a.b.c", "a", true},
		// Not a receiver binding.
		{"task", "", false},     // bare name: the ordinary path handles it
		{"", "", false},         //
		{`m["k"].x`, "", false}, // subscripted
		{"f().y", "", false},    // call-bearing
		{"return.x", "", false}, // keyword root
		{".leading", "", false}, // empty first segment
	} {
		got, ok := dottedAssignRoot(tc.in)
		if ok != tc.ok || got != tc.want {
			t.Errorf("dottedAssignRoot(%q) = (%q,%v), want (%q,%v)", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

// TestReceiverTaintIsScoped: receiver taint is an over-approximation, so it is
// enabled per language rather than everywhere. A language not in the set must
// still ignore a field-assignment target.
func TestReceiverTaintIsScoped(t *testing.T) {
	// Java is deliberately absent: stripJavaDeclType already reads `obj.field`
	// as a `Type name` declaration and binds `field`, which predates receiver
	// taint and is a separate question from it.
	for _, lang := range []langKind{langPython, langJavaScript, langRuby} {
		if receiverTaintLangs[lang] {
			t.Errorf("receiver taint unexpectedly enabled for lang %v", lang)
		}
		lhs, _ := splitAssignment(lang, "obj.field = tainted")
		if lhs != "" {
			t.Errorf("lang %v bound %q from a field assignment without opting in", lang, lhs)
		}
	}
	for _, lang := range []langKind{langSwift, langCPP, langDart} {
		lhs, _ := splitAssignment(lang, "obj.field = tainted")
		if lhs != "obj" {
			t.Errorf("lang %v field assignment bound %q, want obj", lang, lhs)
		}
	}
}
