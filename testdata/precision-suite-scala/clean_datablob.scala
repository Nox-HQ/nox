// Data-blob stressor: a large base64 / data-URI payload embedded in a Scala
// triple-quoted raw string, plus a raw SQL template that contains no interpolated
// untrusted value. These are the noise a broad regex scanner trips on. A precise
// taint scanner fires nothing: the blob is inert data, and the template splices no
// source. Any finding is a false positive.
package assets

object Icons {
  // A base64 data-URI blob in a triple-quoted raw string. No `$` interpolation,
  // no source — it is a constant asset, not code and not a secret flow.
  val logo: String =
    """data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmci
      |AAAAQ29tbWFuZCBleGVjKCkgZXhlY3V0ZVF1ZXJ5KCkgb3BlblN0cmVhbSgpIHJlYWRPYmplY3QoKQ==
      |c3lzLnByb2Nlc3MgUHJvY2VzcyByZWFkQWxsQnl0ZXMgU291cmNlLmZyb21GaWxlIEh0bWwoKQ==""".stripMargin

  // A multi-line SQL TEMPLATE as a triple-quoted string. It mentions executeQuery
  // in prose and contains `//` and `"` that must not be mis-lexed, but it splices
  // no untrusted value — it is a constant, so there is no injectable flow.
  val schemaDoc: String =
    """-- schema.sql : run with `psql`  // not a comment in Scala terms
      |CREATE TABLE users (id BIGINT PRIMARY KEY, name TEXT NOT NULL);
      |-- executeQuery("SELECT * FROM users") is only ever run with constants here""".stripMargin
}
