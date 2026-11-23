package templates

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/discovery"
)

// lines returns the lines XSS-001 reports for one template.
func lines(t *testing.T, path, content string) []int {
	t.Helper()
	var out []int
	for _, f := range scanTemplate(templateKind(path), path, []byte(content)) {
		if f.RuleID != ruleRawOutput {
			t.Fatalf("unexpected rule %s", f.RuleID)
		}
		out = append(out, f.Location.StartLine)
	}
	return out
}

func TestRawTemplateOutput(t *testing.T) {
	cases := []struct {
		name, path, content string
		want                []int
	}{
		// Jinja, Django, Nunjucks
		{"safe filter", "app/templates/note.html", "<p>{{ note.text | safe }}</p>\n", []int{1}},
		{"safe filter without spaces", "app/templates/x.html", "<h1>Hello {{username|safe}},</h1>\n", []int{1}},
		{"safe filter in a .jinja2 file", "views/course.jinja2", "<h2>{{ course.title|safe }}</h2>\n", []int{1}},
		{"a .html outside templates/ with a block tag", "web/page.html", "{% extends 'base.html' %}\n<p>{{ q|safe }}</p>\n", []int{2}},
		{"autoescape off on one line", "templates/i.html",
			"<b>{% autoescape false %}{{search}}{% endautoescape %}</b>\n<p>{{ other }}</p>\n", []int{1}},
		{"autoescape off across lines", "templates/i.html",
			"{% autoescape off %}\n<p>{{ a }}</p>\n<p>{{ b|e }}</p>\n{% endautoescape %}\n<p>{{ c }}</p>\n", []int{2}},
		{"escaped output", "templates/x.html", "<p>{{ note.text }}</p>\n", nil},
		{"safe then escape", "templates/x.html", "<p>{{ note.text|safe|escape }}</p>\n", nil},
		{"a string literal", "templates/x.html", "<p>{{ '<br>'|safe }}</p>\n", nil},
		{"a Django form", "templates/x.html", "{{ form|safe }}\n{{ form.username|safe }}\n", nil},
		{"field help text", "templates/x.html", "<div>{{ field.help_text|safe }}</div>\n", nil},
		{"the CSRF token", "templates/x.html", "const t = \"{{ csrf_token|safe }}\";\n", nil},
		{"inside a template comment", "templates/x.html", "{# {{ q|safe }} #}\n<p>{{ q }}</p>\n", nil},
		{"an Angular template's pipe", "src/app/list.component.html", "<li>{{ item.name | safe }}</li>\n", nil},
		// EJS
		{"EJS raw output", "views/search.ejs", "<h2>Results for: <%- in_query %></h2>\n", []int{1}},
		{"EJS raw output without spaces", "views/p.ejs", "<td><%-product.name%></td>\n", []int{1}},
		{"EJS escaped output", "views/p.ejs", "<td><%= product.name %></td>\n", nil},
		{"EJS layout body", "views/layout.ejs", "<main><%- body %></main>\n<%-body%>\n", nil},
		{"EJS include", "views/p.ejs", "<%- include('header', { title: t }) %>\n<%- include partials/nav %>\n", nil},
		// JSF, Struts, JSP
		{"JSF escape false", "web/messages.xhtml", "<h:outputText value=\"#{m.body}\" escape=\"false\"/>\n", []int{1}},
		{"Struts escape false", "WEB-INF/list.jsp", "<td><s:property value=\"name\" escape=\"false\"/></td>\n", []int{1}},
		{"JSP expression of a request parameter", "WEB-INF/list.jsp",
			"query: <%= request.getParameter(\"searchQuery\") %>\n", []int{1}},
		{"JSF escaped output", "web/messages.xhtml", "<h:outputText value=\"#{m.body}\"/>\n", nil},
		// Not a template
		{"a Python file", "app/views.py", "x = '{{ q|safe }}'\n", nil},
	}
	for _, c := range cases {
		if got := lines(t, c.path, c.content); !slices.Equal(got, c.want) {
			t.Errorf("%s: reported lines %v, want %v", c.name, got, c.want)
		}
	}
}

// TestScanArtifacts reads templates from disk through the analyzer's entry
// point.
func TestScanArtifacts(t *testing.T) {
	dir := t.TempDir()
	rel := filepath.Join("templates", "note.html")
	abs := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte("<p>{{ note.text | safe }}</p>\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	fs, err := NewAnalyzer().ScanArtifacts(context.Background(), []discovery.Artifact{{Path: rel, AbsPath: abs}})
	if err != nil {
		t.Fatal(err)
	}
	got := fs.Findings()
	if len(got) != 1 || got[0].RuleID != "XSS-001" || got[0].Metadata["cwe"] != "CWE-79" {
		t.Fatalf("findings = %+v, want one XSS-001 CWE-79", got)
	}
}
