package appconfig

import (
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

func TestSigningKeyInSource(t *testing.T) {
	jsl, pyl, jl := lexctx.LangJavaScript, lexctx.LangPython, lexctx.LangJava
	for _, c := range []struct {
		name, path string
		lang       lexctx.Lang
		src        string
		want       bool
	}{
		// JavaScript / TypeScript.
		{"jwt.sign literal", "u.js", jsl, "const token = jwt.sign({ _id: user._id.toString() }, 'hardsecret')\n", true},
		{"jwt.verify literal", "a.js", jsl, "const decoded = jwt.verify(token, 'hardsecret')\n", true},
		{"jwt.sign from env", "u.js", jsl, "const token = jwt.sign(payload, process.env.JWT_SECRET)\n", false},
		{"jwt.sign env fallback", "u.js", jsl, "const token = jwt.sign(payload, process.env.JWT_SECRET || 'secret')\n", true},
		{"jwt.sign variable", "u.js", jsl, "const token = jwt.sign(payload, config.secret)\n", false},
		{"express-session secret", "app.js", jsl, "app.use(session({\n  secret: 'keyboard cat',\n  resave: false\n}))\n", true},
		{"express-session secret from env", "app.js", jsl, "app.use(session({ secret: process.env.SESSION_SECRET }))\n", false},
		{"cookie-parser secret", "app.js", jsl, "app.use(cookieParser('s3cr3t'))\n", true},
		{"cookie-session keys", "app.js", jsl, "app.use(cookieSession({ name: 'session', keys: ['key1'] }))\n", true},
		{"secret constant", "r.js", jsl, "const accessTokenSecret = 'hello';\n", true},
		{"secret config property", "all.js", jsl, "module.exports = {\n    cookieSecret: \"session_cookie_secret_key_here\",\n}\n", true},
		{"secret's name, not the secret", "r.js", jsl, "const secretName = 'prod/jwt';\n", false},
		{"value names an env var", "c.js", jsl, "const jwtSecret = 'JWT_SECRET';\n", false},
		{"secret in a comment", "c.js", jsl, "// const jwtSecret = 'hello';\n", false},

		{"key in a test directory", "test/api/2faSpec.ts", jsl, "const secret = 'ASDVAJSDUASZGDIADBJS'\n", false},
		{"key in an e2e spec", "backend/test/auth.e2e-spec.ts", jsl, "const TEST_JWT_SECRET = 'e2e-test-jwt-secret';\n", false},
		{"prefix of a generated key", "k.js", jsl, "const secret = 'whsec_' + crypto.randomBytes(16).toString('hex');\n", false},
		{"preview of a secret", "w.js", jsl, "const secretPreview = 'whsec_1234';\n", false},
		{"placeholder", "p.py", pyl, "secret = \"[....]\"\n", false},

		{"example settings file", "clean_env_example.py", pyl, "JWT_SECRET = \"replace-me-with-a-real-secret\"\n", false},
		{"template config", "config/settings.template.js", jsl, "const jwtSecret = 'replace-me';\n", false},
		{"placeholder default that runs", "backend/app/config.py", pyl, "class Settings(BaseSettings):\n    secret_key: str = \"change-me-in-production\"\n", true},

		// Python.
		{"flask secret_key", "app.py", pyl, "app.secret_key = 'Harry Potter And The Deathly Hallows'\n", true},
		{"flask config SECRET_KEY", "app.py", pyl, "app.config['SECRET_KEY'] = 'Keep it secret, keep it safe'\n", true},
		{"django SECRET_KEY getenv fallback", "settings.py", pyl, "SECRET_KEY = os.getenv(\"DJANGO_SECRET_KEY\", \"unsafe-local-dev-secret-key-change-me\")\n", true},
		{"django SECRET_KEY environ.get split", "settings.py", pyl, "SECRET_KEY = os.environ.get(\n    \"DJANGO_SECRET_KEY\", \"dev-insecure\"\n)\n", true},
		{"django SECRET_KEY no fallback", "settings.py", pyl, "SECRET_KEY = os.environ[\"DJANGO_SECRET_KEY\"]\n", false},
		{"pydantic secret field", "config.py", pyl, "class Settings(BaseSettings):\n    SESSION_SECRET: str = \"dev-only-change-me-please\"\n", true},
		{"pyjwt encode literal", "auth.py", pyl, "tok = jwt.encode({'sub': uid}, 'secret', algorithm='HS256')\n", true},
		{"pyjwt encode variable", "auth.py", pyl, "tok = jwt.encode({'sub': uid}, settings.KEY, algorithm='HS256')\n", false},
		{"AWS secret access key", "c.py", pyl, "aws_secret_access_key = \"wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY\"\n", false},
		{"secret's id", "c.py", pyl, "SECRET_ID = 'arn:aws:secretsmanager:x'\n", false},

		// Java.
		{"auth0 HMAC256 literal", "J.java", jl, "Algorithm alg = Algorithm.HMAC256(\"secret\");\n", true},
		{"auth0 HMAC256 variable", "J.java", jl, "Algorithm alg = Algorithm.HMAC256(secret);\n", false},
		{"jjwt signWith literal", "J.java", jl, "String t = Jwts.builder().signWith(SignatureAlgorithm.HS512, \"victory\").compact();\n", true},
		{"jjwt setSigningKey literal", "J.java", jl, "Jwts.parser().setSigningKey(\"victory\").parseClaimsJws(t);\n", true},
		{"secret String constant", "J.java", jl, "private static final String JWT_SECRET = \"qwertyuiop\";\n", true},
		{"secret's header name", "J.java", jl, "private static final String SECRET_HEADER = \"X-Secret\";\n", false},
	} {
		if got := rulesIn(c.path, c.lang, c.src)[RuleSigningKey]; got != c.want {
			t.Errorf("%s: %s reported = %v, want %v", c.name, RuleSigningKey, got, c.want)
		}
	}
}

// A file naming the secret in both cases: the upper-case literal's lines are
// windowed too when a lower-case one comes later in the file.
func TestSigningKeyBothCases(t *testing.T) {
	src := "const JWT_SECRET = 'qwertyuiop';\nconst secretLabel = 'x';\n"
	if !rulesIn("c.js", lexctx.LangJavaScript, src)[RuleSigningKey] {
		t.Error("JWT_SECRET before a lower-case secret: not reported")
	}
}
