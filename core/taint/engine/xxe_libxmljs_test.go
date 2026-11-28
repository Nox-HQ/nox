package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// libxmljs substitutes entities, and so reads external ones, only when given
// `noent: true`. A parse is an XXE sink when it is given that option and its
// document is untrusted.
func TestLibxmljsNoentXXE(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"noent in the call", `const libxmljs = require('libxmljs');
app.post('/import', (req, res) => {
  const doc = libxmljs.parseXmlString(req.body.xml, { noent: true, noblanks: true });
  res.send(doc.root().text());
});
`, true},
		{"libxmljs2 under another local name", `const libxml = require('libxmljs2');
app.post('/import', (req, res) => {
  const doc = libxml.parseXmlString(req.body.xml, {noent:true});
  res.send(doc.toString());
});
`, true},
		{"noent through an options variable", `const libxmljs = require('libxmljs');
app.post('/import', (req, res) => {
  var parserOptions = { noblanks: true, noent: true, nocdata: true };
  const doc = libxmljs.parseXml(req.body.xml, parserOptions);
  res.send(doc.toString());
});
`, true},
		{"no options", `const libxmljs = require('libxmljs');
app.post('/import', (req, res) => {
  const doc = libxmljs.parseXmlString(req.body.xml);
  res.send(doc.toString());
});
`, false},
		{"options without noent, in a file that sets it elsewhere", `const libxmljs = require('libxmljs');
const trusted = { noent: true };
app.post('/import', (req, res) => {
  const doc = libxmljs.parseXmlString(req.body.xml, { noblanks: true });
  const conf = libxmljs.parseXmlString('<conf/>', trusted);
  res.send(doc.toString() + conf.toString());
});
`, false},
		{"noent set to false", `const libxmljs = require('libxmljs');
app.post('/import', (req, res) => {
  const doc = libxmljs.parseXmlString(req.body.xml, { noent: false });
  res.send(doc.toString());
});
`, false},
		{"a fixed document with noent", `const libxmljs = require('libxmljs');
app.post('/import', (req, res) => {
  const doc = libxmljs.parseXmlString('<a/>', { noent: true, base: req.body.base });
  res.send(doc.toString());
});
`, false},
		{"a parseXmlString that is not libxmljs's", `const xml = require('./xml');
app.post('/import', (req, res) => {
  const doc = xml.parseXmlString(req.body.xml, { noent: true });
  res.send(doc.toString());
});
`, false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "app.js", lexctx.LangJavaScript, c.src), "TAINT-010"); got != c.want {
			t.Errorf("%s: TAINT-010 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
