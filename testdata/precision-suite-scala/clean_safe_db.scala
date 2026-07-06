// Safe database, output, path, and command idioms in Scala — every one is the
// correct, guarded form, so a precise scanner fires nothing. Zero findings
// expected: any finding on this file is a false positive.
package repositories

import java.sql.Connection
import scala.io.Source
import scala.sys.process._

class SafeRepository {
  // Parameterized query: the untrusted id is bound via a PreparedStatement `?`
  // placeholder (setString), never concatenated into the SQL text — no injection.
  def lookupUser(request: Request, conn: Connection): Unit = {
    val id = request.getQueryString("id")
    val stmt = conn.prepareStatement("SELECT name FROM users WHERE id = ?")
    stmt.setString(1, id)
    stmt.executeQuery()
  }

  // Output encoding: the reflected value is HTML-escaped before it becomes trusted
  // markup, so any tags are neutralized — no XSS.
  def greet(request: Request): String = {
    val name = request.getQueryString("name")
    val safe = escapeHtml(name)
    "<h1>Hello " + safe + "</h1>"
  }

  // Path safety: toInt coerces the page number to an integer (throwing on any
  // non-numeric input), so it cannot carry `..` path components.
  def readPage(request: Request): String = {
    val rawPage = request.getQueryString("page")
    val page = rawPage.toInt
    Source.fromFile("/srv/reports/page-" + page + ".txt").mkString
  }

  // Command safety: the port is coerced to an integer before it reaches the
  // process command, so no shell metacharacters can survive.
  def probe(request: Request): Int = {
    val rawPort = request.getQueryString("port")
    val port = rawPort.toInt
    Process("nc -z localhost " + port).run().exitValue()
  }
}
