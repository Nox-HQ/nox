package engine

import (
	"regexp"
	"strings"
)

// XML external entity resolution (XXE, CWE-611) in Java.
//
// Java is the opposite of Python (xxe_python.go): the JDK's DOM, SAX and StAX
// parsers resolve external entities and load external DTDs unless told not
// to. So the vulnerable condition is a parser made from a factory nobody
// hardened, reading a document the caller does not control. The document is
// the taint question, answered by the engine as for every sink; this file
// answers the parser question.
//
// A local is bound to a parser receiver name when the file itself makes a
// factory (DocumentBuilderFactory.newInstance(), SAXParserFactory..., the StAX
// XMLInputFactory..., XMLReaderFactory.createXMLReader()) and hardens nothing.
// The bindings are names declared with a parser or factory type and `var`
// locals assigned from a factory or parser call. The catalog lists the parse
// calls on those receiver names, and the same calls made inline on a factory
// that was never stored and so cannot have been hardened.
//
// Hardening is judged per file and errs toward silence. Any mention of a
// hardening switch -- disallow-doctype-decl, the external-entity features,
// FEATURE_SECURE_PROCESSING, ACCESS_EXTERNAL_DTD, StAX's SUPPORT_DTD and
// IS_SUPPORTING_EXTERNAL_ENTITIES -- counts as hardening, unless every mention
// is a setter call that switches it to the vulnerable value
// (`setFeature(".../external-general-entities", true)`), which is a parser
// someone opened up on purpose. A switch named through a constant, or set to a
// value read from elsewhere, counts as hardened.
//
// A parser that does not come from a factory made in this file -- a
// DocumentBuilder passed in, or one built by a project helper that may harden
// it -- binds to nothing.
//
// Not covered: TransformerFactory and SchemaFactory/Validator (XSLT and schema
// validation also read DTDs), JAXB's Unmarshaller, dom4j's SAXReader and
// JDOM's SAXBuilder, and a factory hardened in one file and used in another.

const (
	xmlDOMFactory  = "xml_dom_factory"
	xmlDOMBuilder  = "xml_dom_builder"
	xmlSAXFactory  = "xml_sax_factory"
	xmlSAXParser   = "xml_sax_parser"
	xmlStAXFactory = "xml_stax_factory"
)

var (
	// A factory made in this file.
	javaXMLFactoryMade = regexp.MustCompile(`\b(?:DocumentBuilderFactory|SAXParserFactory|XMLInputFactory)\s*\.\s*new(?:Default)?(?:NS)?(?:Instance|Factory)\s*\(|\bXMLReaderFactory\s*\.\s*createXMLReader\s*\(`)

	// A name declared with a parser or factory type: a field, parameter or
	// local. The type may be package-qualified.
	javaXMLTypedDecl = regexp.MustCompile(`(?:^|[^\w.])(?:javax\s*\.\s*xml\s*\.\s*(?:parsers|stream)\s*\.\s*|org\s*\.\s*xml\s*\.\s*sax\s*\.\s*)?(DocumentBuilderFactory|DocumentBuilder|SAXParserFactory|SAXParser|XMLReader|XMLInputFactory)\s+([A-Za-z_]\w*)\s*[=;,)]`)

	// `var x = <expression>;`, classified by the call the expression ends in.
	javaXMLVarDecl = regexp.MustCompile(`(?:^|[^\w.])(?:final\s+)?var\s+([A-Za-z_]\w*)\s*=\s*([^;]{1,300});`)
	javaXMLVarRHS  = []struct {
		re   *regexp.Regexp
		kind string
	}{
		{regexp.MustCompile(`\bDocumentBuilderFactory\s*\.\s*new\w*\s*\(\s*\)\s*$`), xmlDOMFactory},
		{regexp.MustCompile(`\.\s*newDocumentBuilder\s*\(\s*\)\s*$`), xmlDOMBuilder},
		{regexp.MustCompile(`\bSAXParserFactory\s*\.\s*new\w*\s*\(\s*\)\s*$`), xmlSAXFactory},
		{regexp.MustCompile(`\.\s*newSAXParser\s*\(\s*\)\s*$|\.\s*getXMLReader\s*\(\s*\)\s*$|\bXMLReaderFactory\s*\.\s*createXMLReader\s*\(\s*\)\s*$`), xmlSAXParser},
		{regexp.MustCompile(`\bXMLInputFactory\s*\.\s*new\w*\s*\(\s*\)\s*$`), xmlStAXFactory},
	}

	// A hardening switch, wherever it is named.
	javaXMLHardeningToken = regexp.MustCompile(`disallow-doctype-decl|external-general-entities|external-parameter-entities|load-external-dtd|FEATURE_SECURE_PROCESSING|ACCESS_EXTERNAL_DTD|accessExternalDTD|IS_SUPPORTING_EXTERNAL_ENTITIES|isSupportingExternalEntities|SUPPORT_DTD|supportDTD`)
	// A setter call, to read the value a switch is set to.
	javaXMLSetter = regexp.MustCompile(`\.\s*set(?:Feature|Property|Attribute)\s*\(([^;]{1,300})\)\s*;`)
	// Switches whose safe value is true (all others are safe when false, or
	// for ACCESS_EXTERNAL_DTD, when empty).
	javaXMLSafeWhenTrue = regexp.MustCompile(`disallow-doctype-decl|FEATURE_SECURE_PROCESSING`)
	javaXMLAccessDTD    = regexp.MustCompile(`ACCESS_EXTERNAL_DTD|accessExternalDTD`)
)

// javaXMLParserBindings maps the names that hold a parser, or the factory of
// one, made in this file from a factory nobody hardened, to the receiver
// names the catalog lists.
func javaXMLParserBindings(content []byte) map[string]string {
	if !javaXMLFactoryMade.Match(content) || javaXMLHardened(content) {
		return nil
	}
	out := map[string]string{}
	typed := map[string]string{
		"DocumentBuilderFactory": xmlDOMFactory, "DocumentBuilder": xmlDOMBuilder,
		"SAXParserFactory": xmlSAXFactory, "SAXParser": xmlSAXParser, "XMLReader": xmlSAXParser,
		"XMLInputFactory": xmlStAXFactory,
	}
	for _, m := range javaXMLTypedDecl.FindAllSubmatch(content, -1) {
		out[string(m[2])] = typed[string(m[1])]
	}
	for _, m := range javaXMLVarDecl.FindAllSubmatch(content, -1) {
		rhs := strings.TrimSpace(string(m[2]))
		for _, r := range javaXMLVarRHS {
			if r.re.MatchString(rhs) {
				out[string(m[1])] = r.kind
				break
			}
		}
	}
	return out
}

// javaXMLHardened reports whether the file names a hardening switch anywhere
// other than in a setter that opens it up.
func javaXMLHardened(content []byte) bool {
	all := len(javaXMLHardeningToken.FindAllIndex(content, -1))
	if all == 0 {
		return false
	}
	opened := 0
	for _, m := range javaXMLSetter.FindAllSubmatch(content, -1) {
		args := string(m[1])
		n := len(javaXMLHardeningToken.FindAllStringIndex(args, -1))
		if n == 0 {
			continue
		}
		if javaXMLSetterOpens(args) {
			opened += n
		}
	}
	return all > opened
}

// javaXMLSetterOpens reports whether a setter's arguments switch a hardening
// switch to its vulnerable value. A value it cannot read is not vulnerable.
func javaXMLSetterOpens(args string) bool {
	i := strings.LastIndex(args, ",")
	if i < 0 {
		return false
	}
	name, value := args[:i], strings.TrimSpace(args[i+1:])
	switch {
	case javaXMLAccessDTD.MatchString(name):
		return strings.HasPrefix(value, `"`) && value != `""`
	case javaXMLSafeWhenTrue.MatchString(name):
		return value == "false" || value == "Boolean.FALSE"
	default:
		return value == "true" || value == "Boolean.TRUE"
	}
}
