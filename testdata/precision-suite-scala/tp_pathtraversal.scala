// Path traversal: a request parameter is concatenated into a filesystem path
// opened via scala.io.Source.fromFile — CWE-22. A correct scanner fires
// TAINT-004. The untrusted name is neither canonicalized nor stripped of `..`
// components, so it can escape the intended directory.
package controllers

import scala.io.Source

class DownloadController {
  // read opens a file whose name comes directly from untrusted input — the bug.
  def read(request: Request): String = {
    val name = request.getQueryString("file")
    val path = "/srv/reports/" + name
    Source.fromFile(path).mkString // nox-expect: TAINT-004
  }
}
