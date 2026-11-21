package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// An HTTP client call is SSRF when its URL is the request's value, and only
// then. The URL can be passed by name -- Python's `url=`, an axios config's
// `url` property -- and when it is, that argument is the URL and nothing else
// the call is given (a JSON body, form data, headers) is.
func TestSSRFJudgesTheURLArgument(t *testing.T) {
	py := func(call string) string {
		return "import requests, httpx\nfrom flask import Flask, request\napp = Flask(__name__)\n\n@app.route('/f')\ndef f():\n    target = request.args.get('u')\n    return " + call + ".text\n"
	}
	js := func(call string) string {
		return "const axios = require('axios');\napp.get('/f', async (req, res) => {\n  const target = req.query.u;\n  const r = await " + call + ";\n  res.send(r.data);\n});\n"
	}
	for _, c := range []struct {
		name string
		lang lexctx.Lang
		src  string
		want bool
	}{
		// The URL by name is the URL.
		{"url= is the URL", lexctx.LangPython, py(`requests.get(url=target)`), true},
		{"url= with a body", lexctx.LangPython, py(`requests.post(url=target, json={"a": 1})`), true},
		{"httpx url=", lexctx.LangPython, py(`httpx.post(url=target, data="x")`), true},
		{"requests.request url=", lexctx.LangPython, py(`requests.request(method="GET", url=target)`), true},
		// A fixed URL by name: the request's value in the body reaches no host.
		{"fixed url=, value in json", lexctx.LangPython, py(`requests.post(url="https://api.example.com/x", json={"next": target})`), false},
		{"fixed url=, value in data", lexctx.LangPython, py(`requests.put(url="https://api.example.com/x", data=target)`), false},
		{"fixed url=, value in headers", lexctx.LangPython, py(`httpx.get(url="https://api.example.com/x", headers={"X-Next": target})`), false},
		// Positional, as before.
		{"positional URL", lexctx.LangPython, py(`requests.delete(target)`), true},
		{"positional fixed URL, value in json", lexctx.LangPython, py(`requests.patch("https://api.example.com/x", json={"url": target})`), false},

		// axios's config object names the URL as a property.
		{"axios config url", lexctx.LangJavaScript, js(`axios({ url: target, method: "get" })`), true},
		{"axios.request config url", lexctx.LangJavaScript, js(`axios.request({ method: "post", url: target })`), true},
		{"axios config baseURL", lexctx.LangJavaScript, js(`axios({ baseURL: target, url: "/v1/items" })`), true},
		{"axios config shorthand url", lexctx.LangJavaScript, "const axios = require('axios');\napp.get('/f', async (req, res) => {\n  const url = req.query.u;\n  const r = await axios({ url });\n  res.send(r.data);\n});\n", true},
		{"axios config fixed url, value in data", lexctx.LangJavaScript, js(`axios({ url: "https://api.example.com/x", method: "post", data: { next: target } })`), false},
		{"axios config fixed url, value in params", lexctx.LangJavaScript, js(`axios.request({ url: "https://api.example.com/x", params: { q: target } })`), false},
		// A config built elsewhere cannot be read: kept as before.
		{"axios config variable", lexctx.LangJavaScript, "const axios = require('axios');\napp.get('/f', async (req, res) => {\n  const cfg = { url: req.query.u };\n  const r = await axios(cfg);\n  res.send(r.data);\n});\n", true},
		// The client methods take the URL first.
		{"axios.post URL", lexctx.LangJavaScript, js(`axios.post(target, { a: 1 })`), true},
		{"axios.put fixed URL, value in body", lexctx.LangJavaScript, js(`axios.put("https://api.example.com/x", { next: target })`), false},
	} {
		got := slices.Contains(analyzeRuleIDs(t, "t"+extFor(c.lang), c.lang, c.src), "TAINT-006")
		if got != c.want {
			t.Errorf("%s: TAINT-006 reported = %v, want %v", c.name, got, c.want)
		}
	}
}
