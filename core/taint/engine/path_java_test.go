package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// An uploaded file's name is chosen by the client: Spring's
// MultipartFile.getOriginalFilename() and the Servlet Part's
// getSubmittedFileName() are request data. And the java.nio.file.Files calls
// that read metadata or list a directory reach the filesystem as much as a
// read does.
func TestJavaPathSinksAndUploadNames(t *testing.T) {
	cases := []struct {
		name, src string
		want      bool
	}{
		{"upload name written under a directory",
			"class A {\n  void up(MultipartFile file) throws Exception {\n    Path target = dir.resolve(file.getOriginalFilename());\n    Files.copy(file.getInputStream(), target);\n  }\n}\n", true},
		{"upload name into a File",
			"class A {\n  void up(MultipartFile file) throws Exception {\n    String name = file.getOriginalFilename();\n    try (FileOutputStream out = new FileOutputStream(new File(base, name))) {\n      out.write(file.getBytes());\n    }\n  }\n}\n", true},
		{"servlet part name",
			"class A {\n  void up(Part part) throws Exception {\n    String name = part.getSubmittedFileName();\n    Files.write(Paths.get(root, name), bytes);\n  }\n}\n", true},
		{"Files.readAttributes",
			"class A {\n  void h(HttpServletRequest request) throws Exception {\n    Path p = Paths.get(base, request.getParameter(\"f\"));\n    BasicFileAttributes a = Files.readAttributes(p, BasicFileAttributes.class);\n  }\n}\n", true},
		{"Files.list",
			"class A {\n  void h(HttpServletRequest request) throws Exception {\n    Path p = root.resolve(request.getParameter(\"d\"));\n    try (var s = Files.list(p)) {\n    }\n  }\n}\n", true},
		{"Files.walk",
			"class A {\n  void h(HttpServletRequest request) throws Exception {\n    Files.walk(Paths.get(request.getParameter(\"d\")));\n  }\n}\n", true},
		{"upload name only logged",
			"class A {\n  void up(MultipartFile file) throws Exception {\n    String name = file.getOriginalFilename();\n    Files.copy(file.getInputStream(), dir.resolve(UUID.randomUUID().toString()));\n  }\n}\n", false},
		{"Files.list on a fixed directory",
			"class A {\n  void h(HttpServletRequest request) throws Exception {\n    String q = request.getParameter(\"q\");\n    try (var s = Files.list(Paths.get(\"/srv/data\"))) {\n    }\n  }\n}\n", false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "A.java", lexctx.LangJava, c.src), "TAINT-004"); got != c.want {
			t.Errorf("%s: TAINT-004 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
