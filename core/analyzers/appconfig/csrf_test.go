package appconfig

import (
	"slices"
	"testing"

	"github.com/nox-hq/nox/core/lexctx"
)

// Spring Security turns CSRF protection off, or off for some routes, in its
// filter chain configuration.
func TestSpringCSRFDisabled(t *testing.T) {
	for _, c := range []struct {
		name, src string
		want      []int
	}{
		{"chained disable", "http\n    .csrf().disable()\n    .authorizeRequests();\n", []int{2}},
		{"lambda disable", "http.csrf(csrf -> csrf.disable());\n", []int{1}},
		{"method reference", "http.csrf(AbstractHttpConfigurer::disable);\n", []int{1}},
		{"reactive spec", "http.csrf(ServerHttpSecurity.CsrfSpec::disable);\n", []int{1}},
		{"routes exempted", "http.csrf(csrf -> csrf.ignoringRequestMatchers(\"/documents/**\"));\n", []int{1}},
		{"chained exemption", "http.csrf().ignoringAntMatchers(\"/api/**\");\n", []int{1}},
		{"exemption list on the next line", "http.csrf(csrf -> csrf\n        .ignoringRequestMatchers(\"/journey/**\"));\n", []int{1}},
		// Not reported.
		{"CSRF configured", "http.csrf(csrf -> csrf.csrfTokenRepository(CookieCsrfTokenRepository.withHttpOnlyFalse()));\n", nil},
		{"default CSRF", "http.csrf(Customizer.withDefaults());\n", nil},
		{"in a comment", "// http.csrf().disable();\n", nil},
		{"another disable", "http.headers().frameOptions().disable();\n", nil},
	} {
		var got []int
		for _, f := range ScanFile("SecurityConfig.java", lexctx.LangJava, []byte(c.src)) {
			if f.RuleID == RuleCSRFDisabled {
				got = append(got, f.Location.StartLine)
			}
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}
