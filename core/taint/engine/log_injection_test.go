package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// A request value written to an application log can carry CR/LF and forge
// log entries (CWE-117). The sink is a call on a logger -- a local or field
// declared or made as one, a Lombok-injected `log`, console, Python's logging
// -- not any method named info or log.
func TestLogInjectionSinks(t *testing.T) {
	cases := []struct {
		name, path string
		lang       lexctx.Lang
		src        string
		want       bool
	}{
		// Java
		{"SLF4J concatenation", "A.java", lexctx.LangJava,
			"class A {\n  private static final Logger log = LoggerFactory.getLogger(A.class);\n  void h(HttpServletRequest request) {\n    String u = request.getParameter(\"u\");\n    log.debug(\"Customer found by username \" + u);\n  }\n}\n", true},
		{"SLF4J placeholder argument", "A.java", lexctx.LangJava,
			"class A {\n  private static final Logger LOGGER = LoggerFactory.getLogger(A.class);\n  void h(HttpServletRequest request) {\n    LOGGER.info(\"path {}\", request.getRequestURI());\n  }\n}\n", true},
		{"Lombok @Slf4j log", "A.java", lexctx.LangJava,
			"@Slf4j\nclass A {\n  void h(HttpServletRequest request) {\n    String t = request.getParameter(\"token\");\n    log.warn(\"token {}\", t);\n  }\n}\n", true},
		{"JBoss Logger format", "A.java", lexctx.LangJava,
			"class A {\n  private static final Logger LOG = Logger.getLogger(A.class);\n  void h(HttpServletRequest request) {\n    LOG.warnf(\"rejected: %s\", request.getParameter(\"u\"));\n  }\n}\n", true},
		{"a log call with a fixed message", "A.java", lexctx.LangJava,
			"class A {\n  private static final Logger log = LoggerFactory.getLogger(A.class);\n  void h(HttpServletRequest request) {\n    String u = request.getParameter(\"u\");\n    log.info(\"login attempt\");\n  }\n}\n", false},
		{"info on something that is not a logger", "A.java", lexctx.LangJava,
			"class A {\n  private final Toast toast = new Toast();\n  void h(HttpServletRequest request) {\n    toast.info(request.getParameter(\"u\"));\n  }\n}\n", false},
		{"a value encoded for the log", "A.java", lexctx.LangJava,
			"class A {\n  private static final Logger log = LoggerFactory.getLogger(A.class);\n  void h(HttpServletRequest request) {\n    String u = Encode.forJava(request.getParameter(\"u\"));\n    log.info(\"user \" + u);\n  }\n}\n", false},
		// JavaScript and TypeScript
		{"console.log of a request value", "routes/session.js", lexctx.LangJavaScript,
			"app.post('/login', (req, res) => {\n  const userName = req.body.userName;\n  console.log(\"Error: attempt to login with invalid user: \", userName);\n});\n", true},
		{"winston logger", "routes/login.js", lexctx.LangJavaScript,
			"const logger = winston.createLogger({});\napp.post('/login', (req, res) => {\n  logger.error(\"Tried to login attempt from user = \" + req.body.user);\n});\n", true},
		{"NestJS Logger field", "src/x.service.ts", lexctx.LangJavaScript,
			"class X {\n  private readonly logger = new Logger(X.name);\n  search(req) {\n    const term = req.query.term;\n    this.logger.log(`comment search term: ${term}`);\n  }\n}\n", true},
		{"JSON.stringify escapes line breaks", "routes/s.js", lexctx.LangJavaScript,
			"app.get('/s', (req, res) => {\n  console.log(\"query \" + JSON.stringify(req.query.q));\n});\n", false},
		{"log on something that is not a logger", "routes/s.js", lexctx.LangJavaScript,
			"const audit = makeAudit();\napp.get('/s', (req, res) => {\n  audit.log(req.query.q);\n});\n", false},
		// Python
		{"logging.warning of a request value", "views.py", lexctx.LangPython,
			"import logging\nfrom flask import request\n\ndef v():\n    user = request.args.get('user')\n    logging.warning(f\"login {user}\")\n", true},
		{"a module logger", "views.py", lexctx.LangPython,
			"import logging\nfrom flask import request\nlogger = logging.getLogger(__name__)\n\ndef v():\n    logger.info(\"search %s\", request.args.get('q'))\n", true},
		{"repr quotes line breaks", "views.py", lexctx.LangPython,
			"import logging\nfrom flask import request\n\ndef v():\n    logging.warning(\"login %s\", repr(request.args.get('user')))\n", false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, c.path, c.lang, c.src), "TAINT-013"); got != c.want {
			t.Errorf("%s: TAINT-013 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
