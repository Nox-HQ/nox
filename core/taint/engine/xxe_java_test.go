package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Java's DOM, SAX and StAX parsers resolve external entities unless their
// factory is hardened. A parse is an XXE sink when the parser comes from a
// factory this file made and never hardened, and the document is untrusted.
func TestJavaXXESinks(t *testing.T) {
	head := "  void handle(HttpServletRequest request) throws Exception {\n    String input = request.getParameter(\"xml\");\n"
	tail := "  }\n}\n"
	dom := "    DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();\n"
	sax := "    SAXParserFactory spf = SAXParserFactory.newInstance();\n"
	stax := "    XMLInputFactory xif = XMLInputFactory.newInstance();\n"
	parseDOM := "    DocumentBuilder b = dbf.newDocumentBuilder();\n    Document d = b.parse(new InputSource(new StringReader(input)));\n"
	cases := []struct {
		name, fields, body string
		want               bool
	}{
		// DOM
		{"DocumentBuilder from an unhardened factory", "", dom + parseDOM, true},
		{"var locals", "",
			"    var f = DocumentBuilderFactory.newInstance();\n    var b = f.newDocumentBuilder();\n    b.parse(new ByteArrayInputStream(input.getBytes()));\n", true},
		{"newDocumentBuilder().parse on a factory local", "", dom + "    Document d = dbf.newDocumentBuilder().parse(new InputSource(new StringReader(input)));\n", true},
		{"a factory made inline", "",
			"    Document d = DocumentBuilderFactory.newInstance().newDocumentBuilder().parse(new InputSource(new StringReader(input)));\n", true},
		{"a factory field", "  private final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n",
			"    Document d = factory.newDocumentBuilder().parse(new InputSource(new StringReader(input)));\n", true},
		{"external entities switched on", "",
			dom + "    dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", true);\n" + parseDOM, true},
		{"doctype disallowed", "",
			dom + "    dbf.setFeature(\"http://apache.org/xml/features/disallow-doctype-decl\", true);\n" + parseDOM, false},
		{"external entities switched off", "",
			dom + "    dbf.setFeature(\"http://xml.org/sax/features/external-general-entities\", false);\n" + parseDOM, false},
		{"external DTD access emptied", "",
			dom + "    dbf.setAttribute(XMLConstants.ACCESS_EXTERNAL_DTD, \"\");\n" + parseDOM, false},
		{"a hardening switch named through a constant", "  private static final String NO_DOCTYPE = \"http://apache.org/xml/features/disallow-doctype-decl\";\n",
			dom + "    dbf.setFeature(NO_DOCTYPE, true);\n" + parseDOM, false},
		{"a fixed document", "", dom + "    DocumentBuilder b = dbf.newDocumentBuilder();\n    Document d = b.parse(getClass().getResourceAsStream(\"/a.xml\"));\n", false},
		{"a DocumentBuilder from elsewhere", "  private final DocumentBuilder b;\n",
			"    Document d = b.parse(new InputSource(new StringReader(input)));\n", false},
		{"a parse on a parser that is not XML's", "  private final CsvParser parser = new CsvParser();\n",
			dom + "    parser.parse(input);\n", false},
		// SAX
		{"SAXParser from an unhardened factory", "",
			sax + "    SAXParser p = spf.newSAXParser();\n    p.parse(new InputSource(new StringReader(input)), handler);\n", true},
		{"SAX factory made inline", "",
			"    SAXParserFactory.newInstance().newSAXParser().parse(new ByteArrayInputStream(input.getBytes()), handler);\n", true},
		{"qualified SAX factory", "",
			"    javax.xml.parsers.SAXParserFactory factory = javax.xml.parsers.SAXParserFactory.newInstance();\n    factory.newSAXParser().parse(new InputSource(new StringReader(input)), handler);\n", true},
		{"XMLReader of an unhardened parser", "",
			sax + "    XMLReader r = spf.newSAXParser().getXMLReader();\n    r.parse(new InputSource(new StringReader(input)));\n", true},
		{"SAX with a fixed document and a tainted handler", "",
			sax + "    SAXParser p = spf.newSAXParser();\n    p.parse(getClass().getResourceAsStream(\"/a.xml\"), new Handler(input));\n", false},
		// StAX
		{"XMLInputFactory with DTD support left on", "",
			stax + "    XMLStreamReader r = xif.createXMLStreamReader(new StringReader(input));\n", true},
		{"XMLInputFactory.newFactory and an event reader", "",
			"    var xif = XMLInputFactory.newFactory();\n    XMLEventReader r = xif.createXMLEventReader(new StringReader(input));\n", true},
		{"XMLInputFactory with DTD support off", "",
			stax + "    xif.setProperty(XMLInputFactory.SUPPORT_DTD, false);\n    XMLStreamReader r = xif.createXMLStreamReader(new StringReader(input));\n", false},
		{"XMLInputFactory with external entities off", "",
			stax + "    xif.setProperty(XMLInputFactory.IS_SUPPORTING_EXTERNAL_ENTITIES, Boolean.FALSE);\n    XMLStreamReader r = xif.createXMLStreamReader(new StringReader(input));\n", false},
	}
	for _, c := range cases {
		src := "\nclass A {\n" + c.fields + head + c.body + tail
		if got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, src), "TAINT-010"); got != c.want {
			t.Errorf("%s: TAINT-010 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
