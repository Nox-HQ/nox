package appconfig

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func linesOf(rule, path string, lang lexctx.Lang, src string) []int {
	var got []int
	for _, f := range ScanFile(path, lang, []byte(src)) {
		if f.RuleID == rule {
			got = append(got, f.Location.StartLine)
		}
	}
	return got
}

// Framing protection switched off: X-Frame-Options disabled, removed or set to
// a value browsers ignore, or a frame-ancestors policy that admits any origin.
func TestFramingProtectionOff(t *testing.T) {
	for _, c := range []struct {
		name, path string
		lang       lexctx.Lang
		src        string
		want       []int
	}{
		{"spring chained", "SecurityConfig.java", lexctx.LangJava, "http.headers().frameOptions().disable();\n", []int{1}},
		{"spring lambda", "SecurityConfig.java", lexctx.LangJava, "http.headers(headers -> headers.frameOptions(frame -> frame.disable()));\n", []int{1}},
		{"spring lambda next line", "SecurityConfig.java", lexctx.LangJava, "http\n    .headers(h -> h\n        .frameOptions(fo -> fo.disable()));\n", []int{3}},
		{"spring method reference", "SecurityConfig.java", lexctx.LangJava, "http.headers(h -> h.frameOptions(HeadersConfigurer.FrameOptionsConfig::disable));\n", []int{1}},
		{"spring all headers off", "SecurityConfig.java", lexctx.LangJava, "http.headers(headers -> headers.disable());\n", []int{1}},
		{"spring all headers off chained", "SecurityConfig.java", lexctx.LangJava, "http.headers().disable();\n", []int{1}},
		{"spring all headers method reference", "SecurityConfig.java", lexctx.LangJava, "http.headers(AbstractHttpConfigurer::disable);\n", []int{1}},
		{"kotlin dsl", "SecurityConfig.kt", lexctx.LangKotlin, "headers {\n    frameOptions { disable() }\n}\n", []int{2}},
		{"servlet ALLOWALL", "ReportController.java", lexctx.LangJava, "response.setHeader(\"X-Frame-Options\", \"ALLOWALL\");\n", []int{1}},
		{"builder ALLOWALL", "FileController.java", lexctx.LangJava, "return HttpResponse.ok(f).header(\"X-Frame-Options\", \"ALLOWALL\");\n", []int{1}},
		{"header removed", "EmbedFilter.java", lexctx.LangJava, "exchange.getResponse().getHeaders().remove(\"X-Frame-Options\");\n", []int{1}},
		{"csp any ancestor", "Filter.java", lexctx.LangJava, "response.setHeader(\"Content-Security-Policy\", \"default-src 'self'; frame-ancestors *\");\n", []int{1}},
		{"express removeHeader", "app.js", lexctx.LangJavaScript, "res.removeHeader('X-Frame-Options');\n", []int{1}},
		{"express set ALLOWALL", "app.js", lexctx.LangJavaScript, "res.set('X-Frame-Options', 'ALLOWALL');\n", []int{1}},
		{"helmet frameguard off", "app.js", lexctx.LangJavaScript, "app.use(helmet({ frameguard: false }));\n", []int{1}},
		{"helmet v7 xFrameOptions off", "app.ts", lexctx.LangJavaScript, "app.use(helmet({\n  xFrameOptions: false,\n}));\n", []int{2}},
		{"django exempt view", "views.py", lexctx.LangPython, "@xframe_options_exempt\ndef embed(request):\n    return render(request, 'x.html')\n", []int{1}},
		{"django ALLOWALL", "settings.py", lexctx.LangPython, "X_FRAME_OPTIONS = 'ALLOWALL'\n", []int{1}},
		{"python header ALLOWALL", "app.py", lexctx.LangPython, "response.headers['X-Frame-Options'] = 'ALLOWALL'\n", []int{1}},
		{"python header deleted", "views.py", lexctx.LangPython, "del response['X-Frame-Options']\n", []int{1}},
		{"one decision, two statements", "embed.ts", lexctx.LangJavaScript, "res.removeHeader('X-Frame-Options');\nres.setHeader('Content-Security-Policy', \"frame-ancestors *\");\n", []int{1}},
		// Not reported.
		{"spring sameOrigin", "SecurityConfig.java", lexctx.LangJava, "http.headers(h -> h.frameOptions(fo -> fo.sameOrigin()));\n", nil},
		{"spring deny", "SecurityConfig.java", lexctx.LangJava, "http.headers().frameOptions().deny();\n", nil},
		{"spring cache control off", "SecurityConfig.java", lexctx.LangJava, "http.headers(h -> h.cacheControl(c -> c.disable()));\n", nil},
		{"csrf off is not framing", "SecurityConfig.java", lexctx.LangJava, "http.csrf().disable();\n", nil},
		{"servlet DENY", "Filter.java", lexctx.LangJava, "response.setHeader(\"X-Frame-Options\", \"DENY\");\n", nil},
		{"csp none", "Filter.java", lexctx.LangJava, "response.setHeader(\"Content-Security-Policy\", \"frame-ancestors 'none'\");\n", nil},
		{"commented", "SecurityConfig.java", lexctx.LangJava, "// http.headers().frameOptions().disable();\n", nil},
		{"in a string", "Doc.java", lexctx.LangJava, "String s = \"http.headers().frameOptions().disable()\";\n", nil},
		{"helmet on", "app.js", lexctx.LangJavaScript, "app.use(helmet({ frameguard: { action: 'deny' } }));\n", nil},
		{"helmet other option off", "app.js", lexctx.LangJavaScript, "app.use(helmet({ contentSecurityPolicy: false }));\n", nil},
		{"frameguard false without helmet", "opts.js", lexctx.LangJavaScript, "const o = { frameguard: false };\n", nil},
		{"django SAMEORIGIN", "settings.py", lexctx.LangPython, "X_FRAME_OPTIONS = 'SAMEORIGIN'\n", nil},
		{"python header DENY", "app.py", lexctx.LangPython, "response.headers['X-Frame-Options'] = 'DENY'\n", nil},
	} {
		if got := linesOf(RuleFramingOff, c.path, c.lang, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}

// Spring Security keeps the pre-login session id after authentication when
// session fixation protection is set to none.
func TestSessionFixationOff(t *testing.T) {
	for _, c := range []struct {
		name, path string
		lang       lexctx.Lang
		src        string
		want       []int
	}{
		{"lambda", "SecurityConfig.java", lexctx.LangJava, "http.sessionManagement(s -> s\n    .sessionFixation(fixation -> fixation.none()));\n", []int{2}},
		{"chained", "SecurityConfig.java", lexctx.LangJava, "http.sessionManagement().sessionFixation().none();\n", []int{1}},
		{"method reference", "SecurityConfig.java", lexctx.LangJava, "s.sessionFixation(SessionManagementConfigurer.SessionFixationConfigurer::none);\n", []int{1}},
		{"kotlin dsl", "SecurityConfig.kt", lexctx.LangKotlin, "sessionManagement {\n    sessionFixation { none() }\n}\n", []int{2}},
		// Not reported.
		{"migrate", "SecurityConfig.java", lexctx.LangJava, "s.sessionFixation(f -> f.migrateSession());\n", nil},
		{"change id", "SecurityConfig.java", lexctx.LangJava, "http.sessionManagement().sessionFixation().changeSessionId();\n", nil},
		{"commented", "SecurityConfig.java", lexctx.LangJava, "// s.sessionFixation(f -> f.none());\n", nil},
	} {
		if got := linesOf(RuleSessionFixationOff, c.path, c.lang, c.src); !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}
