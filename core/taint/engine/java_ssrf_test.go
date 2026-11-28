package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// The HTTP clients a Java service fetches with. Each is a sink on the URL it
// is given, and only on the URL: a value in a URI template variable, a request
// body or a response type is not where the request goes.
func TestJavaSSRFSinks(t *testing.T) {
	head := "class A {\n  void handle(HttpServletRequest request) throws Exception {\n    String target = request.getParameter(\"u\");\n    String id = request.getParameter(\"id\");\n"
	tail := "  }\n}\n"
	cases := []struct {
		name, body string
		want       bool
	}{
		{"RestClient get().uri(url)", "    var r = RestClient.create().get().uri(java.net.URI.create(target)).retrieve().toEntity(byte[].class);\n", true},
		{"WebClient post().uri(url)", "    webClient.post().uri(target).retrieve().bodyToMono(String.class).block();\n", true},
		{"RestClient uri across lines", "    String b = restClient.post()\n        .uri(target)\n        .retrieve().body(String.class);\n", true},
		{"uri template variable", "    webClient.get().uri(\"https://api.example.com/users/{id}\", id).retrieve().bodyToMono(String.class).block();\n", false},
		{"RestTemplate.getForEntity", "    String s = restTemplate.getForEntity(target, String.class).getBody();\n", true},
		{"RestTemplate.postForObject", "    restTemplate.postForObject(target, payload, String.class);\n", true},
		{"RestTemplate with a fixed URL and a tainted variable", "    restTemplate.getForObject(\"https://api.example.com/users/{id}\", String.class, id);\n", false},
		{"HttpRequest.newBuilder(URI)", "    HttpRequest req = HttpRequest.newBuilder(URI.create(target)).GET().build();\n", true},
		{"HttpRequest.newBuilder().uri(URI)", "    HttpRequest req = HttpRequest.newBuilder().uri(URI.create(target)).build();\n", true},
		{"JAX-RS client.target", "    Response up = client.target(target).request(MediaType.APPLICATION_JSON).get();\n", true},
		{"JAX-RS newClient().target", "    Response up = ClientBuilder.newClient().target(target).request().get();\n", true},
		{"Micronaut HttpClient.create", "    BlockingHttpClient c = HttpClient.create(java.net.URI.create(target).toURL()).toBlocking();\n", true},
		{"Jsoup.connect", "    Document d = Jsoup.connect(target).get();\n", true},
		{"Apache HttpGet", "    HttpResponse r = httpClient.execute(new HttpGet(target));\n", true},
		{"Apache HttpPost with a fixed URL", "    HttpPost post = new HttpPost(\"https://api.example.com/hook\");\n    post.setEntity(new StringEntity(id));\n", false},
		{"a get() that is not a request", "    String v = cache.get(target);\n", false},
		{"a uri() on a builder that fetches nothing", "    String link = UriComponentsBuilder.fromUriString(\"/x\").queryParam(\"next\", target).toUriString();\n", false},
		{"a fixed URL", "    String s = restTemplate.getForObject(\"https://api.example.com/status\", String.class);\n", false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, head+c.body+tail), "TAINT-006"); got != c.want {
			t.Errorf("%s: TAINT-006 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
