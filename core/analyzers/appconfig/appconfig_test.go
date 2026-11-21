package appconfig

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func rulesIn(path string, lang lexctx.Lang, src string) map[string]bool {
	out := map[string]bool{}
	for _, f := range ScanFile(path, lang, []byte(src)) {
		out[f.RuleID] = true
	}
	return out
}

func TestSettingsWrittenInSource(t *testing.T) {
	for _, c := range []struct {
		name, path string
		lang       lexctx.Lang
		src, rule  string
		want       bool
	}{
		// APPCFG-001 debug mode.
		{"flask app.run debug", "app.py", lexctx.LangPython, "app.run(host='0.0.0.0', debug=True)\n", RuleDebugMode, true},
		{"flask app.debug", "app.py", lexctx.LangPython, "app.debug = True\n", RuleDebugMode, true},
		{"flask config DEBUG", "app.py", lexctx.LangPython, "app.config['DEBUG'] = True\n", RuleDebugMode, true},
		{"fastapi debug", "main.py", lexctx.LangPython, "app = FastAPI(title='x', debug=True)\n", RuleDebugMode, true},
		{"django settings", "proj/settings.py", lexctx.LangPython, "DEBUG = True\nALLOWED_HOSTS = []\n", RuleDebugMode, true},
		{"debug from the environment", "app.py", lexctx.LangPython, "app.run(debug=os.environ.get('FLASK_DEBUG') == '1')\n", RuleDebugMode, false},
		{"debug off", "app.py", lexctx.LangPython, "app.run(debug=False)\n", RuleDebugMode, false},
		{"django dev settings", "proj/settings/local.py", lexctx.LangPython, "DEBUG = True\n", RuleDebugMode, false},
		{"DEBUG outside settings", "tools/build.py", lexctx.LangPython, "DEBUG = True\n", RuleDebugMode, false},
		{"debug in a comment", "app.py", lexctx.LangPython, "# app.run(debug=True) for local runs\napp.run()\n", RuleDebugMode, false},

		// APPCFG-002 CORS from any origin.
		{"spring addAllowedOriginPattern", "Cors.java", lexctx.LangJava, "config.addAllowedOriginPattern(\"*\");\n", RuleCORSAny, true},
		{"spring allowedOrigins", "Cors.java", lexctx.LangJava, "registry.addMapping(\"/**\").allowedOrigins(\"*\");\n", RuleCORSAny, true},
		{"spring setAllowedOrigins list", "Cors.java", lexctx.LangJava, "c.setAllowedOrigins(List.of(\"*\"));\n", RuleCORSAny, true},
		{"spring @CrossOrigin bare", "Api.java", lexctx.LangJava, "@CrossOrigin\n@RestController\nclass Api {}\n", RuleCORSAny, true},
		{"spring @CrossOrigin star", "Api.java", lexctx.LangJava, "@CrossOrigin(origins = \"*\")\nclass Api {}\n", RuleCORSAny, true},
		{"java header", "F.java", lexctx.LangJava, "response.setHeader(\"Access-Control-Allow-Origin\", \"*\");\n", RuleCORSAny, true},
		{"spring explicit origin", "Cors.java", lexctx.LangJava, "config.addAllowedOrigin(\"https://app.example.com\");\n", RuleCORSAny, false},
		{"@CrossOrigin explicit origin", "Api.java", lexctx.LangJava, "@CrossOrigin(origins = \"https://app.example.com\")\nclass Api {}\n", RuleCORSAny, false},
		{"express cors()", "app.js", lexctx.LangJavaScript, "app.use(cors());\n", RuleCORSAny, true},
		{"express cors origin true", "app.js", lexctx.LangJavaScript, "app.use(cors({ origin: true, credentials: true }));\n", RuleCORSAny, true},
		{"express header star", "app.js", lexctx.LangJavaScript, "res.header('Access-Control-Allow-Origin', '*');\n", RuleCORSAny, true},
		{"express cors list", "app.js", lexctx.LangJavaScript, "app.use(cors({ origin: ['https://app.example.com'] }));\n", RuleCORSAny, false},
		{"flask-cors default", "app.py", lexctx.LangPython, "CORS(app)\n", RuleCORSAny, true},
		{"flask-cors star", "app.py", lexctx.LangPython, "CORS(app, resources={r'/*': {'origins': '*'}})\n", RuleCORSAny, true},
		{"fastapi allow_origins star", "main.py", lexctx.LangPython, "app.add_middleware(CORSMiddleware, allow_origins=['*'])\n", RuleCORSAny, true},
		{"django-cors allow all", "settings.py", lexctx.LangPython, "CORS_ALLOW_ALL_ORIGINS = True\n", RuleCORSAny, true},
		{"flask-cors list", "app.py", lexctx.LangPython, "CORS(app, origins=['https://app.example.com'])\n", RuleCORSAny, false},
		{"fastapi allow_origins list", "main.py", lexctx.LangPython, "app.add_middleware(CORSMiddleware, allow_origins=ORIGINS)\n", RuleCORSAny, false},

		// APPCFG-003 JWT without verification.
		{"pyjwt verify False", "auth.py", lexctx.LangPython, "claims = jwt.decode(token, verify=False)\n", RuleJWTNoVerif, true},
		{"pyjwt verify_signature False", "auth.py", lexctx.LangPython, "claims = jwt.decode(token, options={'verify_signature': False})\n", RuleJWTNoVerif, true},
		{"pyjwt none algorithm", "auth.py", lexctx.LangPython, "claims = jwt.decode(token, key, algorithms=['none'])\n", RuleJWTNoVerif, true},
		{"pyjwt verified", "auth.py", lexctx.LangPython, "claims = jwt.decode(token, key, algorithms=['RS256'])\n", RuleJWTNoVerif, false},
		{"auth0 JWT.decode", "A.java", lexctx.LangJava, "DecodedJWT d = JWT.decode(token);\n", RuleJWTNoVerif, true},
		{"jjwt parse", "A.java", lexctx.LangJava, "Jwt jwt = Jwts.parser().setSigningKey(KEY).parse(token);\n", RuleJWTNoVerif, true},
		{"jjwt parseClaimsJws", "A.java", lexctx.LangJava, "Jws<Claims> j = Jwts.parser().setSigningKey(KEY).parseClaimsJws(token);\n", RuleJWTNoVerif, false},
		{"auth0 verifier", "A.java", lexctx.LangJava, "DecodedJWT d = JWT.require(alg).build().verify(token);\n", RuleJWTNoVerif, false},
		{"jsonwebtoken decode", "auth.js", lexctx.LangJavaScript, "const claims = jwt.decode(token);\n", RuleJWTNoVerif, true},
		{"jsonwebtoken verify", "auth.js", lexctx.LangJavaScript, "const claims = jwt.verify(token, secret);\n", RuleJWTNoVerif, false},
		{"golang-jwt ParseUnverified", "auth.go", lexctx.LangGo, "tok, _, err := parser.ParseUnverified(s, &claims)\n", RuleJWTNoVerif, true},
		{"decode in a string", "auth.js", lexctx.LangJavaScript, "log('call jwt.decode(token) only after verify');\n", RuleJWTNoVerif, false},
	} {
		if got := rulesIn(c.path, c.lang, c.src)[c.rule]; got != c.want {
			t.Errorf("%s: %s reported = %v, want %v", c.name, c.rule, got, c.want)
		}
	}
}
