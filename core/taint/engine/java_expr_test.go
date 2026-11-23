package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Expression languages (SpEL, OGNL, MVEL) and template engines (FreeMarker,
// Velocity, Handlebars) evaluate the string they are given. Each is a sink on
// that string, and only on it: the variables, context or model the expression
// or template is evaluated against hold data, and data placed there is never
// parsed.
func TestJavaExpressionAndTemplateSinks(t *testing.T) {
	head := "  void handle(HttpServletRequest request) throws Exception {\n    String input = request.getParameter(\"q\");\n    Map<String, Object> vars = new HashMap<>();\n"
	tail := "  }\n}\n"
	spring := "import org.springframework.expression.ExpressionParser;\nimport org.springframework.expression.spel.standard.SpelExpressionParser;\n"
	freemarker := "import freemarker.template.Configuration;\nimport freemarker.template.Template;\n"
	cases := []struct {
		name, imports, fields, body, rule string
		want                              bool
	}{
		// SpEL
		{"SpEL through an ExpressionParser field", spring, "  private final ExpressionParser parser = new SpelExpressionParser();\n",
			"    Object v = parser.parseExpression(input).getValue(ctx);\n", "TAINT-005", true},
		{"SpEL through a SpelExpressionParser local", spring, "",
			"    SpelExpressionParser p = new SpelExpressionParser();\n    Object v = p.parseExpression(input).getValue();\n", "TAINT-005", true},
		{"SpEL through var and a qualified constructor", "", "",
			"    var parser = new org.springframework.expression.spel.standard.SpelExpressionParser();\n    Object v = parser.parseExpression(input).getValue();\n", "TAINT-005", true},
		{"SpEL on a parser made inline", spring, "",
			"    Object v = new SpelExpressionParser().parseExpression(input).getValue(ctx);\n", "TAINT-005", true},
		{"SpEL with a fixed expression and a tainted variable", spring, "  private final ExpressionParser parser = new SpelExpressionParser();\n",
			"    ctx.setVariable(\"q\", input);\n    Object v = parser.parseExpression(\"#q.length()\").getValue(ctx);\n", "TAINT-005", false},
		{"a parseExpression on a parser that is not Spring's", "import com.acme.calc.ExpressionParser;\n", "  private final ExpressionParser parser = new ExpressionParser();\n",
			"    Object v = parser.parseExpression(input);\n", "TAINT-005", false},
		// OGNL
		{"Ognl.getValue", "", "", "    Object v = Ognl.getValue(input, vars, vars);\n", "TAINT-005", true},
		{"ognl.Ognl.getValue, qualified", "", "", "    Object v = ognl.Ognl.getValue(input, vars);\n", "TAINT-005", true},
		{"Ognl.parseExpression", "", "", "    Object e = Ognl.parseExpression(input);\n", "TAINT-005", true},
		{"OGNL with a fixed expression and tainted root", "", "",
			"    vars.put(\"q\", input);\n    Object v = Ognl.getValue(\"q.length()\", vars, vars);\n", "TAINT-005", false},
		// MVEL
		{"MVEL.executeExpression", "", "", "    Object v = MVEL.executeExpression(input, vars);\n", "TAINT-005", true},
		{"MVEL.compileExpression", "", "", "    Object v = MVEL.executeExpression(MVEL.compileExpression(input), vars);\n", "TAINT-005", true},
		{"org.mvel2.MVEL.eval, qualified", "", "", "    Object v = org.mvel2.MVEL.eval(input, vars);\n", "TAINT-005", true},
		{"MVEL with a fixed expression and tainted variables", "", "",
			"    vars.put(\"q\", input);\n    Object v = MVEL.eval(\"q.length()\", vars);\n", "TAINT-005", false},
		// Velocity
		{"Velocity.evaluate on a tainted template", "", "",
			"    VelocityContext c = new VelocityContext();\n    StringWriter w = new StringWriter();\n    Velocity.evaluate(c, w, \"notice\", input);\n", "TAINT-003", true},
		{"VelocityEngine.evaluate on a tainted template", "", "  private final VelocityEngine engine = new VelocityEngine();\n",
			"    VelocityContext c = new VelocityContext();\n    StringWriter w = new StringWriter();\n    engine.evaluate(c, w, \"notice\", input);\n", "TAINT-003", true},
		{"Velocity with a fixed template and a tainted context", "", "",
			"    VelocityContext c = new VelocityContext();\n    c.put(\"name\", input);\n    StringWriter w = new StringWriter();\n    Velocity.evaluate(c, w, \"notice\", \"Hello $name\");\n", "TAINT-003", false},
		// FreeMarker
		{"FreeMarker Template from a tainted string", freemarker, "",
			"    Template t = new Template(\"notice\", input, cfg);\n    t.process(vars, out);\n", "TAINT-003", true},
		{"FreeMarker Template from a StringReader", freemarker, "",
			"    Template t = new Template(\"notice\", new StringReader(input), cfg);\n    t.process(vars, out);\n", "TAINT-003", true},
		{"freemarker.template.Template, qualified", "", "",
			"    new freemarker.template.Template(\"notice\", input, cfg).process(vars, out);\n", "TAINT-003", true},
		{"FreeMarker with a fixed template and a tainted model", freemarker, "",
			"    vars.put(\"name\", input);\n    Template t = new Template(\"notice\", \"Hello ${name}\", cfg);\n    t.process(vars, out);\n", "TAINT-003", false},
		{"FreeMarker with a tainted template name and a fixed source", freemarker, "",
			"    Template t = new Template(input, \"Hello\", cfg);\n", "TAINT-003", false},
		{"a Template that is not FreeMarker's", "import com.acme.mail.Template;\n", "",
			"    Template t = new Template(\"notice\", input, 3);\n", "TAINT-003", false},
		// Handlebars
		{"Handlebars.compileInline", "", "  private final Handlebars hb = new Handlebars();\n",
			"    String s = hb.compileInline(input).apply(vars);\n", "TAINT-003", true},
		{"Handlebars with a fixed template and tainted data", "", "  private final Handlebars hb = new Handlebars();\n",
			"    vars.put(\"name\", input);\n    String s = hb.compileInline(\"Hello {{name}}\").apply(vars);\n", "TAINT-003", false},
	}
	for _, c := range cases {
		src := c.imports + "\nclass A {\n" + c.fields + head + c.body + tail
		if got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, src), c.rule); got != c.want {
			t.Errorf("%s: %s reported=%v, want %v", c.name, c.rule, got, c.want)
		}
	}
}
