// Unsafe deserialization: attacker-controlled bytes from the request body are
// deserialized with native Java serialization (ObjectInputStream.readObject),
// a classic remote-code-execution gadget vector — CWE-502. A correct scanner
// fires TAINT-005.
package com.example.session;

import java.io.ObjectInputStream;
import javax.servlet.http.HttpServletRequest;

public class SessionLoader {

    // load reconstructs an object graph from untrusted bytes — the vulnerability.
    public Object load(HttpServletRequest request) throws Exception {
        ObjectInputStream ois = new ObjectInputStream(request.getInputStream());
        return ois.readObject(); // nox-expect: TAINT-005
    }
}
