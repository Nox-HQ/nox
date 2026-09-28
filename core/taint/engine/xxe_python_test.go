package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// XXE needs both halves: a parser with external entities switched on, and a
// document the caller does not control. Each vulnerable case has a clean twin
// missing exactly one of them.
func TestXXEPython(t *testing.T) {
	head := "from flask import request\nimport xml.sax, xml.sax.handler, xml.dom.minidom\nfrom lxml import etree\n\ndef h():\n    bar = request.data\n"
	enableSax := "    parser = xml.sax.make_parser()\n    parser.setFeature(xml.sax.handler.feature_external_ges, True)\n"
	for name, body := range map[string]string{
		"minidom with an entity-resolving sax parser": enableSax + "    doc = xml.dom.minidom.parseString(bar, parser)\n",
		"the parser's own parse":                      enableSax + "    parser.parse(bar)\n",
		"lxml resolve_entities=True":                  "    p = etree.XMLParser(resolve_entities=True)\n    root = etree.fromstring(bar, p)\n",
		"lxml no_network=False":                       "    p = etree.XMLParser(load_dtd=True, no_network=False)\n    tree = etree.parse(bar, parser=p)\n",
		"feature URI spelled out": "    parser = xml.sax.make_parser()\n" +
			"    parser.setFeature('http://xml.org/sax/features/external-general-entities', True)\n    parser.parse(bar)\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+body); !slices.Contains(got, "TAINT-010") {
			t.Errorf("%s: XXE not reported (got %v)", name, got)
		}
	}

	for name, body := range map[string]string{
		"default parser, tainted document": "    parser = xml.sax.make_parser()\n    doc = xml.dom.minidom.parseString(bar, parser)\n",
		"entities on, constant document":   enableSax + "    doc = xml.dom.minidom.parseString('<a/>', parser)\n",
		"feature switched off":             "    parser = xml.sax.make_parser()\n    parser.setFeature(xml.sax.handler.feature_external_ges, False)\n    parser.parse(bar)\n",
		"lxml hardened parser":             "    p = etree.XMLParser(resolve_entities=False, no_network=True)\n    root = etree.fromstring(bar, p)\n",
		"lxml default":                     "    root = etree.fromstring(bar)\n",
	} {
		if got := analyzeRuleIDs(t, "t.py", lexctx.LangPython, head+body); slices.Contains(got, "TAINT-010") {
			t.Errorf("%s: safe parse reported (got %v)", name, got)
		}
	}
}
