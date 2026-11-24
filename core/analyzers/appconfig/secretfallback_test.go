package appconfig

import (
	"slices"
	"testing"
)

// A secret setting whose value is an environment placeholder with a literal
// default runs with that literal wherever the variable is unset. Test values
// below are fixed fixtures, not credentials.
func TestSecretFallback(t *testing.T) {
	for _, c := range []struct {
		name, path, src string
		want            []int
	}{
		{"Spring YAML password", "src/main/resources/application.yml",
			"spring:\n  datasource:\n    password: ${DB_PASSWORD:fixture-pw}\n", []int{3}},
		{"Spring profile YAML secret", "config/application-prod.yaml",
			"auth:\n  token-secret: ${TOKEN_SECRET:fixture-signing-key-32}\n", []int{2}},
		{"Spring properties", "src/main/resources/application.properties",
			"spring.datasource.password=${DB_PASSWORD:fixture-pw}\nserver.port=${PORT:8080}\n", []int{1}},
		{"bootstrap API key", "bootstrap.yml", "vendor:\n  api-key: ${VENDOR_API_KEY:fixture-key}\n", []int{2}},
		{"compose map form", "docker-compose.yml",
			"services:\n  api:\n    environment:\n      JWT_SECRET: ${JWT_SECRET:-fixture-secret}\n", []int{4}},
		{"compose list form", "compose.yaml",
			"services:\n  db:\n    environment:\n      - POSTGRES_PASSWORD=${POSTGRES_PASSWORD:-fixture-pw}\n", []int{4}},
		{"quoted placeholder", "application.yml", "app:\n  secret: \"${APP_SECRET:fixture}\"\n", []int{2}},
		// Not reported.
		{"no default", "application.yml", "spring:\n  datasource:\n    password: ${DB_PASSWORD}\n", nil},
		{"empty default", "application.yml", "spring:\n  datasource:\n    password: ${DB_PASSWORD:}\n", nil},
		{"compose required variable", "docker-compose.yml", "    environment:\n      JWT_SECRET: ${JWT_SECRET:?set it}\n", nil},
		{"default from another variable", "application.yml", "app:\n  secret: ${APP_SECRET:${LEGACY_SECRET}}\n", nil},
		{"a setting about a secret", "application.yml",
			"jwt:\n  token-ttl: ${TOKEN_TTL:3600}\n  secret-header: ${HDR:X-Auth}\n  password-expiry-days: ${EXP:90}\n  key-store-type: ${KS:PKCS12}\n", nil},
		{"commented out", "application.yml", "app:\n  # secret: ${APP_SECRET:fixture}\n", nil},
		{"a Kubernetes manifest", "deploy/deployment.yaml", "env:\n  - name: X\n    password: ${DB_PASSWORD:fixture-pw}\n", nil},
		{"a non-secret setting", "application.yml", "server:\n  port: ${PORT:8080}\n", nil},
	} {
		var got []int
		for _, f := range scanSecretFallback(c.path, []byte(c.src)) {
			if f.RuleID != RuleSecretFallback || f.Metadata["cwe"] != "CWE-798" {
				t.Fatalf("%s: finding %+v", c.name, f)
			}
			got = append(got, f.Location.StartLine)
		}
		if !slices.Equal(got, c.want) {
			t.Errorf("%s: lines %v, want %v", c.name, got, c.want)
		}
	}
}
