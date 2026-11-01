package taintflow

import (
	"slices"
	"testing"
)

// A JVM web framework binds the request into a handler's parameters by
// annotation: Spring's @RequestParam/@PathVariable/@RequestBody, JAX-RS's
// @QueryParam/@PathParam. The value is as untrusted as
// request.getParameter(...), but nothing read it as a source, so a Spring or
// JAX-RS handler passing its parameter to a sink was silent (measured
// 2026-11-01 on v1.55.11). An unannotated parameter stays untainted: a method
// argument may be a trusted, locally derived value.
func TestAnnotatedHandlerParamIsASource(t *testing.T) {
	cases := []struct {
		name, file, src string
		fires           bool
	}{
		{"spring request param into sink", "PingController.java", `
@RestController
public class PingController {
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);
        return "ok";
    }
}
`, true},
		{"spring request param through assignment", "PingController.java", `
@RestController
public class PingController {
    @GetMapping("/ping")
    public String ping(@RequestParam("h") final String host) throws Exception {
        String target = host.trim();
        Runtime.getRuntime().exec("ping " + target);
        return "ok";
    }
}
`, true},
		{"spring path variable, header split across lines", "UserController.java", `
@RestController
public class UserController {
    @GetMapping("/users/{id}")
    public String user(
            @PathVariable(name = "id") String id,
            Model model) throws Exception {
        Runtime.getRuntime().exec("lookup " + id);
        return "user";
    }
}
`, true},
		{"jax-rs query param", "PingResource.java", `
@Path("/ping")
public class PingResource {
    @GET
    public String ping(@QueryParam("host") String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);
        return "ok";
    }
}
`, true},
		{"kotlin spring request param", "PingController.kt", `
@RestController
class PingController {
    @GetMapping("/ping")
    fun ping(@RequestParam host: String): String {
        Runtime.getRuntime().exec("ping " + host)
        return "ok"
    }
}
`, true},
		// Negatives.
		{"unannotated method parameter", "PingService.java", `
public class PingService {
    public String ping(String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);
        return "ok";
    }
}
`, false},
		{"validation annotation is not a request binding", "PingService.java", `
public class PingService {
    public String ping(@Valid @NonNull String host) throws Exception {
        Runtime.getRuntime().exec("ping " + host);
        return "ok";
    }
}
`, false},
		{"annotated parameter unused, constant in sink", "PingController.java", `
@RestController
public class PingController {
    @GetMapping("/ping")
    public String ping(@RequestParam String host) throws Exception {
        Runtime.getRuntime().exec("ping localhost");
        return host;
    }
}
`, false},
		{"kotlin unannotated parameter", "PingService.kt", `
class PingService {
    fun ping(host: String): String {
        Runtime.getRuntime().exec("ping " + host)
        return "ok"
    }
}
`, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ids := scan(t, writeArtifact(t, t.TempDir(), c.file, c.src))
			if got := slices.Contains(ids, "TAINT-002"); got != c.fires {
				t.Errorf("TAINT-002 fired = %v, want %v (findings %v):%s", got, c.fires, ids, c.src)
			}
		})
	}
}

// A sink name called on `super` or `this` is the class's own method. WebGoat's
// path-traversal lesson does `return super.execute(file, fullName, username)`,
// and suffix matching read its own execute() as JDBC Statement.execute: SQL
// injection, in a lesson with no SQL. A field receiver (`this.statement`) is
// still the library object and keeps the sink.
func TestOwnMethodNamedLikeASinkIsNotTheSink(t *testing.T) {
	cases := []struct {
		name, src string
		fires     bool
	}{
		{"super.execute", `
@RestController
public class Upload extends UploadBase {
    @PostMapping("/u")
    public String u(@RequestParam String fullName) {
        return super.execute(fullName);
    }
}
`, false},
		{"this.execute", `
@RestController
public class Upload {
    @PostMapping("/u")
    public String u(@RequestParam String fullName) {
        return this.execute(fullName);
    }
}
`, false},
		{"this.statement.execute keeps the sink", `
@RestController
public class Q {
    @PostMapping("/q")
    public void q(@RequestParam String id) throws Exception {
        this.statement.execute("SELECT * FROM t WHERE id = " + id);
    }
}
`, true},
		{"statement.execute keeps the sink", `
@RestController
public class Q {
    @PostMapping("/q")
    public void q(@RequestParam String id) throws Exception {
        statement.execute("SELECT * FROM t WHERE id = " + id);
    }
}
`, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ids := scan(t, writeArtifact(t, t.TempDir(), "Q.java", c.src))
			if got := slices.Contains(ids, "TAINT-001"); got != c.fires {
				t.Errorf("TAINT-001 fired = %v, want %v (findings %v):%s", got, c.fires, ids, c.src)
			}
		})
	}
}
