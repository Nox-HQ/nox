// Unsafe deserialization: attacker-controlled bytes from the request body are fed
// to native Java serialization via ObjectInputStream.readObject(), a well-known
// RCE gadget vector. This is CWE-502. A correct scanner fires TAINT-005. nox's
// Kotlin taint model sees `ois` derive from the tainted request input stream and
// reach the .readObject sink (matched on the method suffix).
package com.example

import java.io.ObjectInputStream
import javax.servlet.http.HttpServletRequest

class Loader {
    fun load(request: HttpServletRequest) {
        val body = request.getInputStream()
        val ois = ObjectInputStream(body)
        val obj = ois.readObject() // nox-expect: TAINT-005
    }
}
