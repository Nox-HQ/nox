package engine

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Java mass assignment: a request-bound object copied wholesale onto an
// entity, or a property chosen by the request set through reflection.
func TestMassAssignmentJava(t *testing.T) {
	ctl := "import org.springframework.web.bind.annotation.*;\nimport org.springframework.beans.BeanUtils;\n\n@RestController\nclass C {\n"
	cases := []struct {
		name, body string
		want       bool
	}{
		{"copyProperties from a @ModelAttribute form", "  @PostMapping(\"/p\")\n  public String save(@ModelAttribute ProfileForm form) {\n    Employee e = repo.findById(1L).get();\n    BeanUtils.copyProperties(form, e);\n    return \"ok\";\n  }\n", true},
		{"copyProperties from a @RequestBody DTO", "  @PutMapping(\"/u\")\n  public User upd(@RequestBody UserDto dto) {\n    User u = new User();\n    org.springframework.beans.BeanUtils.copyProperties(dto, u, \"id\");\n    return u;\n  }\n", true},
		{"through a service helper", "  @PostMapping(\"/p\")\n  public String save(@ModelAttribute ProfileForm form) {\n    apply(form);\n    return \"ok\";\n  }\n  void apply(ProfileForm details) {\n    BeanUtils.copyProperties(details, employee);\n  }\n", true},
		{"setPropertyValue with request keys", "  @PostMapping(\"/p\")\n  public void upd(@RequestBody Map<String, Object> body) {\n    BeanWrapper w = new BeanWrapperImpl(product);\n    for (Map.Entry<String, Object> entry : body.entrySet()) {\n      w.setPropertyValue(entry.getKey(), entry.getValue());\n    }\n  }\n", true},
		{"Apache Commons copy reads its second argument", "  @PostMapping(\"/p\")\n  public String save(@ModelAttribute ProfileForm form) {\n    org.apache.commons.beanutils.BeanUtils.copyProperties(employee, form);\n    return \"ok\";\n  }\n", true},
		{"a property named by a request parameter", "  @PostMapping(\"/p\")\n  public void upd(@RequestParam String field, @RequestParam String v) {\n    w.setPropertyValue(field, v);\n  }\n", true},
		// Not mass assignment.
		{"a request value under a fixed property name", "  @PostMapping(\"/p\")\n  public void upd(@RequestParam String field, @RequestParam String v) {\n    w.setPropertyValue(\"name\", v + field);\n  }\n", false},
		{"Apache Commons copy INTO the form", "  @PostMapping(\"/p\")\n  public String save(@ModelAttribute ProfileForm form) {\n    org.apache.commons.beanutils.BeanUtils.copyProperties(form, employee);\n    return \"ok\";\n  }\n", false},
		{"Spring copy INTO the form", "  @PostMapping(\"/p\")\n  public String save(@ModelAttribute ProfileForm form) {\n    BeanUtils.copyProperties(employee, form);\n    return \"ok\";\n  }\n", false},
		{"a String body is not an object", "  @PostMapping(\"/p\")\n  public void save(@RequestBody String raw) {\n    BeanUtils.copyProperties(raw, e);\n  }\n", false},
		{"copyProperties into the DTO (response side)", "  @GetMapping(\"/u\")\n  public UserDto get(@RequestParam Long id) {\n    UserDto dto = new UserDto();\n    BeanUtils.copyProperties(repo.find(id), dto);\n    return dto;\n  }\n", false},
		{"copyProperties from a field of the form", "  @PostMapping(\"/p\")\n  public String save(@ModelAttribute ProfileForm form) {\n    BeanUtils.copyProperties(form.getAddress(), e);\n    return \"ok\";\n  }\n", false},
		{"setPropertyValue with a fixed name", "  @PostMapping(\"/p\")\n  public void upd(@RequestParam String v) {\n    w.setPropertyValue(\"name\", v);\n  }\n", false},
	}
	for _, c := range cases {
		if got := slices.Contains(analyzeRuleIDs(t, "src/main/java/C.java", lexctx.LangJava, ctl+c.body+"}\n"), "TAINT-014"); got != c.want {
			t.Errorf("%s: TAINT-014 reported=%v, want %v", c.name, got, c.want)
		}
	}
}
