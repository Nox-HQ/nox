package appconfig

import "testing"

func TestDebugConfig(t *testing.T) {
	cases := []struct {
		name, path, src string
		want            []int
	}{
		{"stack trace always (properties)", "src/main/resources/application.properties", "server.port=8080\nserver.error.include-stacktrace=always\n", []int{2}},
		{"stack trace on param (yaml)", "src/main/resources/application.yml", "server:\n  error:\n    include-stacktrace: on_param\n", []int{3}},
		{"all actuator endpoints (properties)", "src/main/resources/application.properties", "management.endpoints.web.exposure.include=*\n", []int{1}},
		{"all actuator endpoints (yaml)", "src/main/resources/application.yml", "management:\n  endpoints:\n    web:\n      exposure:\n        include: \"*\"\n", []int{5}},
		{"H2 console (properties)", "src/main/resources/application.properties", "spring.h2.console.enabled=true\n", []int{1}},
		{"H2 console (yaml)", "src/main/resources/application.yml", "spring:\n  h2:\n    console:\n      enabled: true\n", []int{4}},
		{"JSF development stage behind a comment", "src/main/webapp/WEB-INF/web.xml", "<context-param>\n  <param-name>jakarta.faces.PROJECT_STAGE</param-name>\n  <!-- local only -->\n  <param-value>Development</param-value>\n</context-param>\n", []int{2}},
		// Not reported.
		{"stack trace never", "src/main/resources/application.properties", "server.error.include-stacktrace=never\n", nil},
		{"named actuator endpoints", "src/main/resources/application.properties", "management.endpoints.web.exposure.include=health,info\n", nil},
		{"a wildcard include under another key", "src/main/resources/application.yml", "spring:\n  config:\n    import:\n      include: \"*\"\n", nil},
		{"enabled under a console that is not H2", "src/main/resources/application.yml", "logging:\n  console:\n    enabled: true\n", nil},
		{"stack trace never (yaml)", "src/main/resources/application.yml", "server:\n  error:\n    include-stacktrace: never\n", nil},
		{"enabled under H2 but not its console", "src/main/resources/application.yml", "spring:\n  h2:\n    datasource:\n      enabled: true\n", nil},
		{"H2 console off", "src/main/resources/application.properties", "spring.h2.console.enabled=false\n", nil},
		{"a development profile", "src/main/resources/application-dev.yml", "server:\n  error:\n    include-stacktrace: always\n", nil},
		{"a local profile", "src/main/resources/application-local.properties", "spring.h2.console.enabled=true\n", nil},
		{"JSF production stage", "src/main/webapp/WEB-INF/web.xml", "<param-name>jakarta.faces.PROJECT_STAGE</param-name>\n<param-value>Production</param-value>\n", nil},
	}
	for _, c := range cases {
		var got []int
		for _, f := range scanDebugConfig(c.path, []byte(c.src)) {
			if f.RuleID != RuleDebugMode {
				t.Errorf("%s: rule %s", c.name, f.RuleID)
			}
			got = append(got, f.Location.StartLine)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
			}
		}
	}
}
