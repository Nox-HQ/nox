// Reflected XSS: a request parameter is wrapped in play.twirl.api.Html, which
// marks the string as trusted markup and bypasses Twirl's auto-escaping — CWE-79.
// A correct scanner fires TAINT-003. Because the value is reflected into the HTML
// response without encoding, an attacker-supplied `<script>` executes.
package controllers

import play.twirl.api.Html

class GreetingController {
  // greet reflects an un-encoded request value into trusted HTML — the bug.
  def greet(request: Request): Html = {
    val name = request.getQueryString("name")
    Html("<h1>Hello " + name + "</h1>") // nox-expect: TAINT-003
  }
}
