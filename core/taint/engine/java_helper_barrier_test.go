package engine

import "testing"

// javaHelperFile is a servlet that passes a request parameter through a helper
// method and prints what comes back. call is the helper call, body the
// helper's statements before `return bar;`.
func javaHelperFile(call, body string) string {
	return `class S {
	void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
		String param = request.getParameter("p");
		String bar = ` + call + `;
		response.getWriter().print(bar);
	}
	private class Test {
		public String doSomething(HttpServletRequest request, String param) throws Exception {
` + body + `
			return bar;
		}
	}
	private String own(HttpServletRequest request, String param) {
` + body + `
		return bar;
	}
}`
}

// A helper method of this file's own classes decides what its call returns:
// called bare, on this, or on an object constructed in place with no
// arguments. One that returns a constant is a barrier; one that returns its
// argument carries it.
func TestJavaOwnHelperDecidesItsReturn(t *testing.T) {
	const constant = `			String bar = "safe!";`
	const passthrough = `			String bar = param;`
	calls := map[string]string{
		"constructed in place": `new Test().doSomething(request, param)`,
		"bare":                 `own(request, param)`,
		"this":                 `this.own(request, param)`,
	}
	for name, call := range calls {
		t.Run(name+" constant", func(t *testing.T) {
			if flows := analyzeJavaFile(t, javaHelperFile(call, constant)); hasRule(flows, "TAINT-003") {
				t.Errorf("a helper returning a constant: want no TAINT-003; got %v", ruleIDs(flows))
			}
		})
		t.Run(name+" passthrough", func(t *testing.T) {
			if flows := analyzeJavaFile(t, javaHelperFile(call, passthrough)); !hasRule(flows, "TAINT-003") {
				t.Errorf("a helper returning its argument: want TAINT-003; got %v", ruleIDs(flows))
			}
		})
	}
}

// What the barrier must not cover: an object built from the request, and a
// call on a receiver of another type that only shares the local method's name.
func TestJavaHelperBarrierLimits(t *testing.T) {
	// The constructor takes the parameter, so the object may carry it.
	ctorArg := `class S {
	void doPost(HttpServletRequest request, HttpServletResponse response) throws Exception {
		String param = request.getParameter("p");
		String bar = new Holder(param).doSomething(request, param);
		response.getWriter().print(bar);
	}
	private class Holder {
		public String doSomething(HttpServletRequest request, String param) {
			String bar = "safe!";
			return bar;
		}
	}
}`
	if flows := analyzeJavaFile(t, ctorArg); !hasRule(flows, "TAINT-003") {
		t.Errorf("constructor taking the parameter: want TAINT-003; got %v", ruleIDs(flows))
	}
	// A factory call is not a constructor: what helper() returns is of a type
	// this file does not show, whose doSomething only shares the local name.
	if flows := analyzeJavaFile(t, javaHelperFile(`helper().doSomething(request, param)`, `			String bar = "safe!";`)); !hasRule(flows, "TAINT-003") {
		t.Errorf("method on a factory's result: want TAINT-003; got %v", ruleIDs(flows))
	}
	// Inside the helper, thing.doSomething is ThingInterface's method, not the
	// helper itself: it is unknown, and an unknown call carries its argument.
	viaInterface := `			ThingInterface thing = ThingFactory.createThing();
			String bar = thing.doSomething(param);`
	if flows := analyzeJavaFile(t, javaHelperFile(`new Test().doSomething(request, param)`, viaInterface)); !hasRule(flows, "TAINT-003") {
		t.Errorf("same-named method on another type: want TAINT-003; got %v", ruleIDs(flows))
	}
}

// An HTML decoder undoes an escaper in the same statement.
func TestJavaDecoderUndoesEscaper(t *testing.T) {
	const head = `class X {
	void render(HttpServletRequest request, HttpServletResponse resp) throws Exception {
		String p = request.getParameter("p");
`
	cases := map[string]string{
		"assigned":    "String bar = ESAPI.encoder().decodeForHTML(ESAPI.encoder().encodeForHTML(p));\n\t\tresp.getWriter().print(bar);",
		"at the sink": "resp.getWriter().print(ESAPI.encoder().decodeForHTML(ESAPI.encoder().encodeForHTML(p)));",
		"commons":     "String bar = StringEscapeUtils.unescapeHtml4(StringEscapeUtils.escapeHtml4(p));\n\t\tresp.getWriter().print(bar);",
		"spring":      "resp.getWriter().print(HtmlUtils.htmlUnescape(HtmlUtils.htmlEscape(p)));",
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			if flows := analyzeJavaFile(t, head+"\t\t"+body+"\n\t}\n}"); !hasRule(flows, "TAINT-003") {
				t.Errorf("want TAINT-003; got %v", ruleIDs(flows))
			}
		})
	}
	// The escaper alone still clears.
	clean := head + "\t\tString bar = ESAPI.encoder().encodeForHTML(p);\n\t\tresp.getWriter().print(bar);\n\t}\n}"
	if flows := analyzeJavaFile(t, clean); hasRule(flows, "TAINT-003") {
		t.Errorf("escaper alone: want no TAINT-003; got %v", ruleIDs(flows))
	}
}
