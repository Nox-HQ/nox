package engine

import "testing"

// append, printf and format write to the response only on a writer the
// response hands out: inline `resp.getWriter().format(...)`, or a local
// assigned from getWriter(). Keyed on the method alone they would name
// StringBuilder.append and String.format, so the clean cases pin those silent.
func TestJavaResponseWriterSinks(t *testing.T) {
	const head = `class X {
	void render(HttpServletRequest request, HttpServletResponse resp) throws Exception {
		String p = request.getParameter("p");
`
	const tail = `
	}
}`
	vulnerable := map[string]string{
		"inline append":           `resp.getWriter().append(p);`,
		"inline printf format":    `resp.getWriter().printf(p, "a");`,
		"inline format locale":    `resp.getWriter().format(java.util.Locale.US, p, "a");`,
		"inline format argument":  "Object[] obj = {\"a\", p};\n\t\tresp.getWriter().printf(\"%s %s\", obj);",
		"local writer format":     "java.io.PrintWriter out = resp.getWriter();\n\t\tout.format(\"<p>%s</p>\", p);",
		"var writer append chain": "var w = resp.getWriter();\n\t\tw.append(\"<p>\").append(p);",
	}
	for name, body := range vulnerable {
		t.Run(name, func(t *testing.T) {
			flows := analyzeJavaFile(t, head+"\t\t"+body+tail)
			if !hasRule(flows, "TAINT-003") {
				t.Errorf("want TAINT-003; got %v", ruleIDs(flows))
			}
		})
	}
	clean := map[string]string{
		"StringBuilder append":      "StringBuilder sb = new StringBuilder();\n\t\tsb.append(p);",
		"String format":             `String s = String.format("x %s", p);`,
		"StringWriter append":       "java.io.StringWriter sw = new java.io.StringWriter();\n\t\tsw.append(p);",
		"Formatter format":          "java.util.Formatter f = new java.util.Formatter();\n\t\tf.format(\"%s\", p);",
		"ESAPI encodeForHTML":       `resp.getWriter().print(org.owasp.esapi.ESAPI.encoder().encodeForHTML(p));`,
		"Commons Lang escapeHtml":   `resp.getWriter().print(org.apache.commons.lang.StringEscapeUtils.escapeHtml(p));`,
		"OWASP Encode content":      `resp.getWriter().print(org.owasp.encoder.Encode.forHtmlContent(p));`,
		"OWASP Encode attribute":    `resp.getWriter().print(Encode.forHtmlAttribute(p));`,
		"jsoup clean":               `resp.getWriter().print(Jsoup.clean(p, Safelist.basic()));`,
		"escaped then format":       "String e = StringEscapeUtils.escapeHtml(p);\n\t\tresp.getWriter().format(\"%s\", e);",
		"constant to writer append": `resp.getWriter().append("<p>static</p>");`,
	}
	for name, body := range clean {
		t.Run("clean "+name, func(t *testing.T) {
			flows := analyzeJavaFile(t, head+"\t\t"+body+tail)
			if hasRule(flows, "TAINT-003") {
				t.Errorf("want no TAINT-003; got %v", ruleIDs(flows))
			}
		})
	}
}
