package appconfig

import (
	"strings"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestCookieFlags(t *testing.T) {
	const (
		ho  = RuleCookieHTTPOnly
		sec = RuleCookieSecure
	)
	jsl, pyl, jl := lexctx.LangJavaScript, lexctx.LangPython, lexctx.LangJava
	for _, c := range []struct {
		name, path string
		lang       lexctx.Lang
		src, rule  string
		want       bool
	}{
		// Omitted flags on a session or credential cookie.
		{"express auth cookie no options", "r.js", jsl, "res.cookie('auth_token', token)\n", ho, true},
		{"express auth cookie no options secure", "r.js", jsl, "res.cookie('auth_token', token)\n", sec, true},
		{"express cookie named by value", "r.js", jsl, "res.cookie(\"Auth\", accessToken)\n", ho, true},
		{"express options without httpOnly", "r.js", jsl, "res.cookie('userAuthToken', n, {maxAge: 3600000, path: '/'});\n", ho, true},
		{"express both flags set", "r.js", jsl, "res.cookie('auth_token', token, { httpOnly: true, secure: true })\n", ho, false},
		{"express both flags set secure", "r.js", jsl, "res.cookie('auth_token', token, { httpOnly: true, secure: true })\n", sec, false},
		{"express flag from a switch", "r.js", jsl, "res.cookie('sid', s, { httpOnly: true, secure: isProd })\n", sec, false},
		{"express preference cookie", "r.js", jsl, "res.cookie('theme', 'dark')\n", ho, false},
		{"express options by name", "r.js", jsl, "res.cookie('session', s, cookieOptions)\n", ho, false},
		{"next cookies().set object", "route.ts", jsl, "cookies().set({ name: 'sessionId', value: token, path: '/' })\n", ho, true},
		{"next res.cookies.set", "route.ts", jsl, "res.cookies.set(\"sessionId\", token, { path: '/' })\n", sec, true},
		{"cookie call in a comment", "r.js", jsl, "// res.cookie('auth_token', token)\n", ho, false},
		{"express-session no cookie.secure", "app.js", jsl, "app.use(session({ secret: 'k', resave: false }))\n", sec, true},
		{"express-session cookie.secure", "app.js", jsl, "app.use(session({ secret: 'k', cookie: { secure: true } }))\n", sec, false},
		{"session() that is not middleware", "app.js", jsl, "const s = session({ user: u })\n", sec, false},
		{"flask session cookie", "app.py", pyl, "response.set_cookie('vulpy_session', session)\n", ho, true},
		{"flask session cookie secure", "app.py", pyl, "response.set_cookie(\"session\", username)\n", sec, true},
		{"flask key= value=", "app.py", pyl, "resp.set_cookie(key='auth_cookie', value=c)\n", ho, true},
		{"flask flags set", "app.py", pyl, "resp.set_cookie('session', s, httponly=True, secure=True)\n", ho, false},
		{"flask preference cookie", "app.py", pyl, "resp.set_cookie('preferences', prefs)\n", ho, false},
		{"framework's own set_cookie", "resp.py", pyl, "    def set_cookie(self, session_token, value):\n", ho, false},
		{"servlet session cookie", "C.java", jl, "Cookie c = new Cookie(\"JSESSIONID\", id);\nresponse.addCookie(c);\n", ho, true},
		{"servlet cookie with flags", "C.java", jl, "Cookie c = new Cookie(\"token\", t);\nc.setHttpOnly(true);\nc.setSecure(true);\nresponse.addCookie(c);\n", ho, false},
		{"servlet cookie with flags secure", "C.java", jl, "Cookie c = new Cookie(\"token\", t);\nc.setHttpOnly(true);\nc.setSecure(true);\nresponse.addCookie(c);\n", sec, false},
		{"servlet basket cookie", "C.java", jl, "response.addCookie(new Cookie(\"b_id\", basketId));\n", ho, false},
		{"ResponseCookie without flags", "C.java", jl, "ResponseCookie c = ResponseCookie.from(\"refresh_token\", t).path(\"/\").build();\n", sec, true},
		{"ResponseCookie with flags", "C.java", jl, "ResponseCookie c = ResponseCookie.from(\"refresh_token\", t).httpOnly(true).secure(true).build();\n", sec, false},

		{"servlet cookie deleted", "C.java", jl, "Cookie emptyCookie = new Cookie(\"token\", \"\");\n", ho, false},
		{"flask cookie deleted", "app.py", pyl, "response.set_cookie('vulpy_session', '', expires=0)\n", sec, false},
		{"flask cookie set to None", "app.py", pyl, "response.set_cookie(\"session_id\", None)\n", ho, false},
		{"express cookie deleted", "r.js", jsl, "res.cookie('auth_token', '', { maxAge: 0 })\n", ho, false},

		// Flags switched off in writing, on any cookie.
		{"express httpOnly false", "r.js", jsl, "res.cookie('theme', v, { httpOnly: false })\n", ho, true},
		{"express-session secure false", "app.js", jsl, "app.use(session({\n  secret: 'k',\n  cookie: { secure: false }\n}))\n", sec, true},
		{"nodemailer secure false", "mail.js", jsl, "nodemailer.createTransport({ host: h, port: 587, secure: false })\n" + strings.Repeat("// pad\n", 60) + "res.cookie('theme', 'dark')\n", sec, false},
		{"flask httponly False", "app.py", pyl, "resp.set_cookie('theme', v, httponly=False)\n", ho, true},
		{"django SESSION_COOKIE_SECURE False", "settings.py", pyl, "SESSION_COOKIE_SECURE = False\n", sec, true},
		{"django SESSION_COOKIE_HTTPONLY False", "settings.py", pyl, "SESSION_COOKIE_HTTPONLY = False\n", ho, true},
		{"java setHttpOnly false", "C.java", jl, "cookie.setHttpOnly(false);\n", ho, true},
	} {
		if got := rulesIn(c.path, c.lang, c.src)[c.rule]; got != c.want {
			t.Errorf("%s: %s reported = %v, want %v", c.name, c.rule, got, c.want)
		}
	}
}

func TestCookieFlagsInConfiguration(t *testing.T) {
	for _, c := range []struct {
		name, path, src, rule string
		want                  bool
	}{
		{"spring yaml secure false", "src/main/resources/application.yml", "server:\n  servlet:\n    session:\n      cookie:\n        secure: false\n", RuleCookieSecure, true},
		{"spring yaml http-only false", "application.yaml", "server:\n  servlet:\n    session:\n      cookie:\n        http-only: false\n", RuleCookieHTTPOnly, true},
		{"yaml secure false elsewhere", "application.yml", "spring:\n  mail:\n    properties:\n      secure: false\n", RuleCookieSecure, false},
		{"spring properties", "application.properties", "server.servlet.session.cookie.secure=false\n", RuleCookieSecure, true},
		{"spring properties true", "application.properties", "server.servlet.session.cookie.secure=true\n", RuleCookieSecure, false},
		{"tomcat useHttpOnly false", "META-INF/context.xml", "<Context reloadable=\"false\" useHttpOnly=\"false\">\n", RuleCookieHTTPOnly, true},
		{"tomcat useHttpOnly true", "META-INF/context.xml", "<Context useHttpOnly=\"true\">\n", RuleCookieHTTPOnly, false},
	} {
		got := false
		for _, f := range scanCookieConfig(c.path, []byte(c.src)) {
			got = got || f.RuleID == c.rule
		}
		if got != c.want {
			t.Errorf("%s: %s reported = %v, want %v", c.name, c.rule, got, c.want)
		}
	}
}
