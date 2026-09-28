package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// XPath (TAINT-008) and LDAP (TAINT-009) injection had no sink class at all,
// so a request value spliced into an XPath expression or an LDAP filter was
// invisible. Each vulnerable case here has a clean twin that differs only in
// the one thing that makes it safe, so a case cannot pass by accident.
const pyHandlerHead = "from flask import request\n\ndef h():\n    bar = request.args.get('q')\n"

func TestXPathInjectionPython(t *testing.T) {
	for name, body := range map[string]string{
		"lxml element xpath": "    import lxml.etree\n    root = lxml.etree.parse(fd)\n" +
			"    query = f\"/Employees/Employee[@emplid='{bar}']\"\n    nodes = root.xpath(query)\n",
		"lxml compiled XPath": "    import lxml.etree\n    query = f\"/E[@id='{bar}']\"\n" +
			"    run_query = lxml.etree.XPath(query)\n    nodes = run_query(root)\n",
		"from lxml import etree": "    from lxml import etree\n    q = '/E[@id=' + bar + ']'\n    f = etree.XPath(q)\n",
		"elementpath select": "    import elementpath\n    query = f\"/E[@id='{bar}']\"\n" +
			"    nodes = elementpath.select(root, query)\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, pyHandlerHead+body); !slices.Contains(got, "TAINT-008") {
			t.Errorf("%s: XPath injection not reported (got %v)", name, got)
		}
	}

	for name, body := range map[string]string{
		// XPath variables are bound by the engine, not parsed as XPath.
		"parameterized xpath": "    query = \"/Employees/Employee[@emplid=$name]\"\n    nodes = root.xpath(query, name=bar)\n",
		// The document being user-supplied is not an injection into the path.
		"tainted document, constant path": "    import elementpath\n    nodes = elementpath.select(bar, '/E[@id=1]')\n",
		"constant query":                  "    nodes = root.xpath(\"/E[@id='1']\")\n",
		"numeric coercion":                "    n = int(bar)\n    nodes = root.xpath(f\"/E[@id='{n}']\")\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, pyHandlerHead+body); slices.Contains(got, "TAINT-008") {
			t.Errorf("%s: safe XPath reported (got %v)", name, got)
		}
	}
}

func TestLDAPInjectionPython(t *testing.T) {
	flt := "    filter = f'(&(objectclass=person)(uid={bar}))'\n"
	for name, body := range map[string]string{
		"ldap3 connection from a project factory": "    import helpers.ldap\n    conn = helpers.ldap.get_connection()\n" +
			flt + "    conn.search('ou=users', filter)\n",
		"ldap3.Connection": "    import ldap3\n    c = ldap3.Connection(server)\n" + flt + "    c.search('ou=users', filter)\n",
		"with ldap3.Connection as": "    import ldap3\n    with ldap3.Connection(server, user=u) as conn:\n" +
			"        conn.search('ou=users', f'(uid={bar})')\n",
		"python-ldap search_s": "    import ldap\n    l = ldap.initialize(uri)\n" + flt + "    l.search_s('ou=users', ldap.SCOPE_SUBTREE, filter)\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, pyHandlerHead+body); !slices.Contains(got, "TAINT-009") {
			t.Errorf("%s: LDAP injection not reported (got %v)", name, got)
		}
	}

	for name, body := range map[string]string{
		"escaped filter value": "    import ldap3\n    from ldap3.utils.conv import escape_filter_chars\n" +
			"    c = ldap3.Connection(server)\n    safe = escape_filter_chars(bar)\n" +
			"    c.search('ou=users', f'(uid={safe})')\n",
		// `search` on anything not made by LDAP is not an LDAP query.
		"re.search":           "    import re\n    m = re.search(bar, text)\n",
		"vector store search": "    index = VectorStore()\n    hits = index.search(bar)\n",
		"constant filter":     "    import ldap3\n    c = ldap3.Connection(server)\n    c.search('ou=users', '(uid=admin)')\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, pyHandlerHead+body); slices.Contains(got, "TAINT-009") {
			t.Errorf("%s: safe LDAP query reported (got %v)", name, got)
		}
	}
}

func TestLDAPReceiverBindingFromImportedConnection(t *testing.T) {
	src := "from flask import request\nfrom ldap3 import Connection\n\ndef h():\n    bar = request.args.get('q')\n" +
		"    conn = Connection(server)\n    conn.search('ou=users', f'(uid={bar})')\n"
	if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, src); !slices.Contains(got, "TAINT-009") {
		t.Errorf("Connection imported by name from ldap3 was not bound (got %v)", got)
	}
}
