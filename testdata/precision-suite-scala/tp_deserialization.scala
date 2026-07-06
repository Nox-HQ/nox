// Unsafe deserialization: attacker-controlled request bytes are fed into a native
// ObjectInputStream — CWE-502. A correct scanner fires TAINT-005. Native Java/
// Scala serialization instantiates arbitrary types from the byte stream, a
// well-known remote-code-execution vector; the tainted bytes enter at the stream
// construction.
package controllers

import java.io.ObjectInputStream

class SessionController {
  // restore deserializes untrusted request bytes with no type allow-list — the bug.
  // The stream construction and readObject are a single expression, so the tainted
  // bytes reach the native deserializer in one statement.
  def restore(request: Request): AnyRef = {
    val blob = request.body
    new ObjectInputStream(blob).readObject() // nox-expect: TAINT-005
  }
}
