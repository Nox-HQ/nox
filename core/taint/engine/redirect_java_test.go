package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Spring MVC redirects by returning a view name: `return "redirect:" + url`.
// It is no call, so no catalog sink could name it. JAX-RS and Micronaut
// redirect through a response builder given a URI.
func TestJavaRedirectSinks(t *testing.T) {
	spring := "import org.springframework.stereotype.Controller;\n"
	head := "class A {\n  String h(HttpServletRequest request) {\n    String url = request.getParameter(\"next\");\n"
	tail := "  }\n}\n"
	cases := []struct {
		name, imports, body string
		want                bool
	}{
		{"return a redirect view", spring, "    return \"redirect:\" + url;\n", true},
		{"ModelAndView redirect", spring, "    return new ModelAndView(\"redirect:\" + url);\n", true},
		{"assigned view name", spring, "    String view = \"redirect:\" + url;\n    return view;\n", true},
		{"RedirectView", spring, "    return new RedirectView(url);\n", true},
		{"JAX-RS seeOther", "import javax.ws.rs.core.Response;\n", "    return Response.seeOther(URI.create(url)).build();\n", true},
		{"Micronaut redirect", "import io.micronaut.http.HttpResponse;\n", "    return HttpResponse.seeOther(URI.create(url));\n", true},
		{"a fixed redirect", spring, "    return \"redirect:/home\";\n", false},
		{"a fixed redirect beside a tainted read", spring, "    log(url);\n    return \"redirect:/home\";\n", false},
		{"a fixed path with a value after it", spring, "    return \"redirect:/items/\" + url;\n", false},
		{"Micronaut redirect to a fixed path", "import io.micronaut.http.HttpResponse;\n", "    return HttpResponse.seeOther(URI.create(\"/cohorts/\" + url));\n", false},
		{"Micronaut redirect built on a fixed path", "import io.micronaut.http.HttpResponse;\n", "    return HttpResponse.seeOther(UriBuilder.of(\"/password/reset\").queryParam(\"t\", url).build());\n", false},
		{"servlet redirect to a fixed path", "", "    response.sendRedirect(\"/items?id=\" + url);\n", false},
		{"servlet redirect to the value", "", "    response.sendRedirect(url);\n", true},
		{"protocol-relative literal", "", "    response.sendRedirect(\"//\" + url);\n", true},
		{"a fixed-path redirect in one branch, the value in another", "",
			"    if (locked) {\n      response.sendRedirect(\"/login\" + q);\n    } else if (ok) {\n      response.sendRedirect(url);\n    }\n", true},
		{"not a Spring file", "", "    return \"redirect:\" + url;\n", false},
	}
	for _, c := range cases {
		src := c.imports + head + c.body + tail
		if got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, src), "TAINT-007"); got != c.want {
			t.Errorf("%s: TAINT-007 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
