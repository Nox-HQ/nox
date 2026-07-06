// Placeholder / constant configuration values in Scala. None of these strings is
// derived from untrusted input: they are hardcoded config defaults and example
// values. A precise taint scanner fires nothing here — there is no source, so no
// flow. Any finding is a false positive.
package config

import scala.io.Source

object AppConfig {
  // Constant connection settings — not a taint source and not concatenated with
  // any untrusted value.
  val dbHost = "localhost"
  val dbName = "appdb"
  val apiKeyPlaceholder = "REPLACE_WITH_YOUR_API_KEY"
  val defaultReportPath = "/srv/reports/summary.txt"

  // Reading a constant, developer-controlled path is not path traversal: the file
  // name is a literal, never influenced by request input.
  def loadBanner(): String = {
    Source.fromFile(defaultReportPath).mkString
  }

  // A query built entirely from constants is not injectable — no source reaches
  // it. The `sql` interpolator here splices only literal, trusted table names.
  def health(): String = {
    val table = "health_check"
    val query = s"SELECT 1 FROM $table LIMIT 1"
    query
  }
}
