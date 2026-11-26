package engine

import (
	"bytes"
	"regexp"
	"strings"
)

// Python receiver bindings: a local that holds a DB-API cursor or connection
// stands for `cursor` or `connection` in a call chain, and one that holds an
// LDAP connection for `ldap_connection`.
//
// The catalog names Python's SQL sinks by receiver -- cursor.execute,
// connection.execute -- and chains are matched as written, so the sink matched
// only when the variable was literally named `cursor` or `connection`. What
// people write is `cur = con.cursor()`, `c = db.cursor()`,
// `with conn.cursor() as c:`. Every SQL case in the OWASP Benchmark for Python
// is written that way; nox reported none of them.
//
// The binding is read from how the value was made, not from its name: a local
// assigned from `<anything>.cursor(...)` is a cursor, one assigned from
// `<anything>.connect(...)` is a connection. Like import aliases, the resolved
// chain is ADDED beside the original (see applyImportAliases), so a call that
// matched before still matches and nothing can be lost. The binding is
// file-wide, as the import table is: a same-named local elsewhere in the file
// gains a redundant chain, not a removed one.
var (
	pyAssignFromCall = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*[^=].*\.(cursor|connect)\s*\(`)
	pyWithAsCall     = regexp.MustCompile(`^\s*(?:async\s+)?with\s+.*\.(cursor|connect)\s*\([^)]*\)\s+as\s+([A-Za-z_]\w*)\s*:`)
)

var pyReceiverKind = map[string]string{"cursor": "cursor", "connect": "connection"}

// pyLoggerMade binds a module or local logger: `logger = logging.getLogger(...)`,
// structlog's `get_logger()`, loguru's `logger` imported by name is the module.
var pyLoggerMade = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*(?:logging\s*\.\s*getLogger|structlog\s*\.\s*get_logger|getLogger)\s*\(`)

// An LDAP connection is bound the same way, from what made it. ldap3's
// `Connection.search(base, filter)` is the injection sink, but `search` is
// the most generic method name there is -- `re.search`, a vector store's
// `index.search(query)` -- so the sink cannot be keyed on it. A local assigned
// from a call whose chain names LDAP (`ldap3.Connection(...)`,
// `ldap.initialize(...)`, a project's `helpers.ldap.get_connection()`), or
// from ldap3's Connection imported by name, stands for `ldap_connection`, and
// only `ldap_connection.search` is a sink.
var (
	pyAssignFromAnyCall = regexp.MustCompile(`^\s*([A-Za-z_]\w*)\s*=\s*([A-Za-z_][\w.]*)\s*\(`)
	pyWithAsAnyCall     = regexp.MustCompile(`^\s*(?:async\s+)?with\s+([A-Za-z_][\w.]*)\s*\(.*\)\s+as\s+([A-Za-z_]\w*)\s*:`)
)

// madeByLDAP reports whether a constructor or factory chain produces an LDAP
// connection: a segment naming LDAP, or a name imported from an LDAP module.
func madeByLDAP(chain string, imports map[string]string) bool {
	for _, seg := range strings.Split(chain, ".") {
		if strings.Contains(strings.ToLower(seg), "ldap") {
			return true
		}
	}
	head, _, _ := strings.Cut(chain, ".")
	return strings.Contains(strings.ToLower(imports[head]), "ldap")
}

// pythonReceiverBindings maps each local that holds a cursor or connection to
// the receiver name the catalog uses for it.
func pythonReceiverBindings(content []byte) map[string]string {
	out := map[string]string{}
	imports := pythonAliases(content)
	for _, line := range strings.Split(string(content), "\n") {
		if m := pyLoggerMade.FindStringSubmatch(line); m != nil {
			out[m[1]] = "app_logger"
			continue
		}
		if m := pyAssignFromCall.FindStringSubmatch(line); m != nil {
			out[m[1]] = pyReceiverKind[m[2]]
			continue
		}
		if m := pyWithAsCall.FindStringSubmatch(line); m != nil {
			out[m[2]] = pyReceiverKind[m[1]]
			continue
		}
		if m := pyAssignFromAnyCall.FindStringSubmatch(line); len(m) == 3 && madeByLDAP(m[2], imports) {
			out[m[1]] = "ldap_connection"
			continue
		}
		if m := pyWithAsAnyCall.FindStringSubmatch(line); len(m) == 3 && madeByLDAP(m[1], imports) {
			out[m[2]] = "ldap_connection"
		}
	}
	return out
}

// Java receiver bindings, by declared type. Java states a local's type, so an
// XPath evaluator or an LDAP directory context is known from its declaration
// -- `javax.xml.xpath.XPath xp = xpf.newXPath();`, `DirContext ctx = ...` --
// and only calls on such a local are XPath or LDAP sinks. Keyed on the method
// name alone, `evaluate` and `search` would match expression engines, search
// indexes and every other API that uses the words.
var (
	javaXPathDecl = regexp.MustCompile(`(?:^|[^\w.])(?:javax\s*\.\s*xml\s*\.\s*xpath\s*\.\s*)?XPath\s+([A-Za-z_]\w*)\s*=`)
	javaLDAPDecl  = regexp.MustCompile(`(?:^|[^\w.])(?:javax\s*\.\s*naming\s*\.\s*(?:directory|ldap)\s*\.\s*)?(?:Initial)?(?:Dir|Ldap)Context\s+([A-Za-z_]\w*)\s*=`)
	// A ProcessBuilder's program is set by its constructor or by command(...),
	// and `command` alone names far too many methods to be a sink.
	javaProcessBuilderDecl = regexp.MustCompile(`(?:^|[^\w.])(?:java\s*\.\s*lang\s*\.\s*)?ProcessBuilder\s+([A-Za-z_]\w*)\s*=`)
	javaProcessBuilderVar  = regexp.MustCompile(`(?:^|[^\w.])(?:var|final\s+var)\s+([A-Za-z_]\w*)\s*=\s*new\s+(?:java\s*\.\s*lang\s*\.\s*)?ProcessBuilder\s*\(`)

	// Expression and template engines. `parseExpression`, `evaluate` and
	// `compileInline` are names many APIs use, so only a call on a local of
	// the engine's type is a sink. A Spring parser is declared as its
	// interface (`ExpressionParser parser = new SpelExpressionParser()`), a
	// name any expression library could use, so that declaration counts only
	// in a file that imports Spring's expression package.
	javaSpelDecl           = regexp.MustCompile(`(?:^|[^\w.])(?:org\s*\.\s*springframework\s*\.\s*expression\s*\.\s*(?:spel\s*\.\s*standard\s*\.\s*)?)?(Spel)?ExpressionParser\s+([A-Za-z_]\w*)\s*=`)
	javaSpelVar            = regexp.MustCompile(`(?:^|[^\w.])(?:var|final\s+var)\s+([A-Za-z_]\w*)\s*=\s*new\s+(?:org\s*\.\s*springframework\s*\.\s*expression\s*\.\s*spel\s*\.\s*standard\s*\.\s*)?SpelExpressionParser\s*\(`)
	javaVelocityEngineDecl = regexp.MustCompile(`(?:^|[^\w.])(?:org\s*\.\s*apache\s*\.\s*velocity\s*\.\s*app\s*\.\s*)?VelocityEngine\s+([A-Za-z_]\w*)\s*=`)
	javaHandlebarsDecl     = regexp.MustCompile(`(?:^|[^\w.])(?:com\s*\.\s*github\s*\.\s*jknack\s*\.\s*handlebars\s*\.\s*)?Handlebars\s+([A-Za-z_]\w*)\s*=`)
	// FreeMarker's template class is `Template`, which is also what a mail,
	// report or CMS model calls its own class. Written unqualified it is
	// FreeMarker's only in a file that imports it.
	javaFreemarkerImport = regexp.MustCompile(`(?m)^\s*import\s+freemarker\s*\.\s*template\s*\.\s*(?:Template|\*)\s*;`)
)

// A response writer. print, println and write are sinks by method name, but
// append, printf and format are not: alone they name StringBuilder.append and
// String.format. They are sinks on a writer the response hands out -- a local
// assigned from `<anything>.getWriter()`, which is what `PrintWriter out =
// response.getWriter();` and `var out = resp.getWriter();` both are -- and on
// the inline `response.getWriter().format(...)` chain (catalog key
// getWriter.format).
var javaWriterFromResponse = regexp.MustCompile(`(?:^|[^\w.])([A-Za-z_]\w*)\s*=\s*[A-Za-z_][\w.]*\s*\.\s*getWriter\s*\(\s*\)`)

// Application loggers (CWE-117). `info`, `warn` and `log` are names half of
// every API uses, so a call is a log sink only on a receiver this file declares
// or makes as a logger: a `Logger`/`Log` local or field (SLF4J, Log4j, JUL,
// JBoss, Commons Logging), or the `log` field a Lombok logging annotation
// injects.
var (
	javaLoggerDecl   = regexp.MustCompile(`(?:^|[^\w.])(?:[a-z]\w*\s*\.\s*)*(?:Logger|Log|XLogger|FluentLogger)\s+([A-Za-z_]\w*)\s*[=;]`)
	javaLombokLogger = regexp.MustCompile(`(?m)^\s*@(?:lombok\s*\.\s*(?:extern\s*\.\s*\w+\s*\.\s*)?)?(?:Slf4j|XSlf4j|Log4j2?|Log|CommonsLog|JBossLog|Flogger|CustomLog)\b`)
)

// javaReceiverBindings maps each local declared as an XPath or an LDAP
// directory context to the receiver name the catalog uses for it.
func javaReceiverBindings(content []byte) map[string]string {
	out := map[string]string{}
	for _, m := range javaXPathDecl.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "xpath_object"
	}
	for _, m := range javaLDAPDecl.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "ldap_dircontext"
	}
	for _, re := range []*regexp.Regexp{javaProcessBuilderDecl, javaProcessBuilderVar} {
		for _, m := range re.FindAllSubmatch(content, -1) {
			out[string(m[1])] = "process_builder"
		}
	}
	springExpr := bytes.Contains(content, []byte("org.springframework.expression"))
	for _, m := range javaSpelDecl.FindAllSubmatch(content, -1) {
		if len(m[1]) > 0 || springExpr {
			out[string(m[2])] = "spel_parser"
		}
	}
	for _, m := range javaSpelVar.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "spel_parser"
	}
	for _, m := range javaWriterFromResponse.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "response_writer"
	}
	for _, m := range javaVelocityEngineDecl.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "velocity_engine"
	}
	for _, m := range javaHandlebarsDecl.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "handlebars"
	}
	if javaFreemarkerImport.Match(content) {
		out["Template"] = "freemarker.template.Template"
	}
	for _, m := range javaLoggerDecl.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "app_logger"
	}
	if javaLombokLogger.Match(content) {
		if _, declared := out["log"]; !declared {
			out["log"] = "app_logger"
		}
	}
	// XML parsers from a factory nobody hardened: see xxe_java.go.
	for name, kind := range javaXMLParserBindings(content) {
		out[name] = kind
	}
	return out
}

// PHP receiver bindings, from what made the value. The catalog names PHP's
// database and XML sinks by receiver -- mysqli.query, pdo.query -- and chains
// match as written, so `$conn = new mysqli(...); $conn->query($q)`, the most
// common way to write it, matched nothing. A local assigned from a
// constructor or factory of one of these classes stands for the receiver name
// the catalog uses.
var phpReceiverMakers = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`\$([A-Za-z_]\w*)\s*=\s*(?:new\s+\\?mysqli\s*\(|mysqli_connect\s*\(|mysqli_init\s*\()`), "mysqli"},
	{regexp.MustCompile(`\$([A-Za-z_]\w*)\s*=\s*new\s+\\?PDO\s*\(`), "pdo"},
	{regexp.MustCompile(`\$([A-Za-z_]\w*)\s*=\s*(?:new\s+\\?SimpleXMLElement\s*\(|simplexml_load_(?:file|string)\s*\()`), "simplexml"},
	{regexp.MustCompile(`\$([A-Za-z_]\w*)\s*=\s*new\s+\\?DOMXPath\s*\(`), "domxpath"},
}

// phpReceiverBindings maps each local made by one of phpReceiverMakers to the
// receiver name the catalog uses for it.
func phpReceiverBindings(content []byte) map[string]string {
	out := map[string]string{}
	for _, m := range phpReceiverMakers {
		for _, g := range m.re.FindAllSubmatch(content, -1) {
			out[string(g[1])] = m.kind
		}
	}
	return out
}

// C# receiver bindings, by declared type. The catalog names ASP.NET's request
// and response by the property name the page and controller base classes
// expose -- Request.QueryString, Response.Write -- so a handler that takes
// them as parameters, `void Bad(HttpRequest req, HttpResponse resp)`, or holds
// them in a local, matched nothing. A name declared with one of these types
// stands for the catalog's receiver.
var csharpTypedDecl = []struct {
	re   *regexp.Regexp
	kind string
}{
	{regexp.MustCompile(`(?:^|[^\w.])(?:System\s*\.\s*Web\s*\.\s*)?(?:HttpRequest|HttpRequestBase|HttpRequestWrapper)\s+([A-Za-z_]\w*)\s*[,)=;]`), "Request"},
	{regexp.MustCompile(`(?:^|[^\w.])(?:System\s*\.\s*Web\s*\.\s*)?(?:HttpResponse|HttpResponseBase|HttpResponseWrapper)\s+([A-Za-z_]\w*)\s*[,)=;]`), "Response"},
	// XPath and LDAP are keyed on the declared type for the reason Java's are
	// (see javaReceiverBindings): Evaluate, Select and FindOne are too generic
	// to be sinks by method name.
	{regexp.MustCompile(`(?:^|[^\w.])XPathNavigator\s+([A-Za-z_]\w*)\s*[,)=;]`), "XPathNavigator"},
	{regexp.MustCompile(`(?:^|[^\w.])(?:XmlDocument|XmlNode|XmlElement)\s+([A-Za-z_]\w*)\s*[,)=;]`), "XmlNode"},
	{regexp.MustCompile(`(?:^|[^\w.])DirectorySearcher\s+([A-Za-z_]\w*)\s*[,)=;]`), "DirectorySearcher"},
}

// csharpReceiverBindings maps each name declared as an HTTP request or
// response to the receiver name the catalog uses for it.
func csharpReceiverBindings(content []byte) map[string]string {
	out := map[string]string{}
	for _, d := range csharpTypedDecl {
		for _, m := range d.re.FindAllSubmatch(content, -1) {
			if name := string(m[1]); name != d.kind {
				out[name] = d.kind
			}
		}
	}
	return out
}

// JavaScript receiver bindings, from what made the value. The catalog names
// Node's SQL sinks by receiver -- db.query, pool.query, connection.query -- so
// `const client = new pg.Client(); client.query(sql)` or `const conn = await
// mysql.createConnection(cfg)` matched nothing. `query` alone is far too
// generic to be a sink (GraphQL clients, query builders, URL helpers), so the
// handle is bound from the driver call that made it.
var jsReceiverMakers = regexp.MustCompile(`(?:^|[\s;(,])(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*=\s*(?:await\s+)?(?:` +
	`new\s+(?:[A-Za-z_$][\w$]*\.)?(?:Client|Pool)\s*\(` + // pg
	`|(?:[A-Za-z_$][\w$]*\.)?create(?:Connection|Pool)\s*\(` + // mysql, mysql2
	`|new\s+(?:[A-Za-z_$][\w$]*\.)?Database\s*\(` + // sqlite3, better-sqlite3
	`|[A-Za-z_$]*(?:pool|Pool)\.(?:connect|getConnection)\s*\(\s*\)` + // a pooled connection
	`)`)

// javascriptReceiverBindings maps each local made by a SQL driver to `db`.
// jsLoggerMakers binds a local or class field made as a logger: NestJS's
// `new Logger(...)`, winston, pino, bunyan, log4js, or a `createLogger` helper.
var jsLoggerMakers = regexp.MustCompile(`(?:^|[\s;(,])(?:const|let|var)?\s*([A-Za-z_$][\w$]*)\s*(?::\s*[\w.<>]+\s*)?=\s*(?:` +
	`new\s+(?:[A-Za-z_$][\w$]*\.)?(?:Logger|ConsoleLogger)\s*\(` +
	`|(?:winston|bunyan)\s*\.\s*createLogger\s*\(` +
	`|createLogger\s*\(` +
	`|pino\s*\(` +
	`|log4js\s*\.\s*getLogger\s*\(` +
	`)`)

func javascriptReceiverBindings(content []byte) map[string]string {
	out := map[string]string{}
	for _, m := range jsLoggerMakers.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "app_logger"
	}
	for _, m := range jsReceiverMakers.FindAllSubmatch(content, -1) {
		if name := string(m[1]); name != "db" {
			out[name] = "db"
		}
	}
	return out
}

// rubyPGConnection binds a local made by the pg gem -- `conn = PG.connect(...)`,
// `PG::Connection.new(...)` -- to `pg`, so its exec/exec_params/prepare are
// the catalog's pg sinks and a `conn` of any other kind is not.
var rubyPGConnection = regexp.MustCompile(`(?m)^\s*@?([A-Za-z_]\w*)\s*=\s*PG(?:::Connection)?\s*\.\s*(?:connect|new|open)\b`)

func rubyReceiverBindings(content []byte) map[string]string {
	out := map[string]string{}
	for _, m := range rubyPGConnection.FindAllSubmatch(content, -1) {
		out[string(m[1])] = "pg"
	}
	return out
}
