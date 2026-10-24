package iac

import "testing"

// The shape of every case here is the same: a configuration that got WORSE read
// the same as, or better than, the one before it. A scanner that stays quiet
// while a Secret moves into plaintext, a bucket opens to the world or a
// container gains SYS_ADMIN is not reporting a clean repo, it is reporting
// nothing. Each case is a true positive paired with the safe form of the same
// resource, and every safe form is the real hardened spelling rather than a
// string shaped to dodge the pattern.

const k8sDeploymentHead = `apiVersion: apps/v1
kind: Deployment
metadata:
  name: invoicely
spec:
  template:
    spec:
`

const pinnedImage = "ghcr.io/example/invoicely:1.0.0@sha256:1a526b97cace6b4006256570efa1a29cd1fe4b96a5301f8d48e87c5139438a45"

func TestFalseAllClear_RuleFiresOnlyOnTheInsecureForm(t *testing.T) {
	cases := []struct {
		name string
		rule string
		path string
		body string
		want int // findings of rule
	}{
		// ---- 2. a credential-named env var with a literal value ----------
		{
			name: "k8s literal DB_PASSWORD",
			rule: "IAC-502", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          env:\n            - name: DB_PASSWORD\n              value: \"hunter2-prod-Passw0rd\"\n",
		},
		{
			name: "k8s literal API key, unquoted, flow-style entry",
			rule: "IAC-502", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          env:\n            - {name: PAYMENTS_API_KEY, value: Zx9pQ4mN7vB2kL8w}\n",
		},
		{
			name: "k8s secretKeyRef is the correct form",
			rule: "IAC-502", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef: {name: invoicely-db, key: password}\n",
		},
		{
			name: "k8s credential-named variable that holds a path, a URL or a header name",
			rule: "IAC-502", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          env:\n            - name: DB_PASSWORD_FILE\n              value: /run/secrets/db_password\n            - name: OAUTH_TOKEN_URL\n              value: https://auth.example.com/oauth/token\n            - name: API_KEY_HEADER\n              value: X-Api-Key\n            - name: SECRET_NAME\n              value: invoicely-db\n",
		},
		{
			name: "k8s templated, empty or placeholder values are not literals",
			rule: "IAC-502", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          env:\n            - name: DB_PASSWORD\n              value: \"\"\n            - name: API_TOKEN\n              value: $(VAULT_TOKEN)\n            - name: SMTP_PASSWORD\n              value: ${SMTP_PASSWORD}\n            - name: SESSION_SECRET\n              value: \"<set-me>\"\n",
		},
		{
			name: "an INSERT_TOKEN_HERE style template value is a placeholder",
			rule: "IAC-502", path: "etcd.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: etcd\n          image: " + pinnedImage + "\n          env:\n            - name: ETCD_DISCOVERY_TOKEN\n              value: INSERT_ETCD_DISCOVERY_TOKEN\n            - name: API_KEY\n              value: your-api-key\n",
		},
		{
			name: "helm values list env with a literal password",
			rule: "IAC-502", path: "values.yaml", want: 1,
			body: "replicaCount: 2\nenv:\n  - name: SMTP_PASSWORD\n    value: \"hunter2-prod-Passw0rd\"\n",
		},
		{
			name: "helm template expression is not a literal",
			rule: "IAC-502", path: "deployment.yaml", want: 0,
			body: "env:\n  - name: SMTP_PASSWORD\n    value: {{ .Values.smtp.password | quote }}\n",
		},
		{
			name: "compose list entry with a literal secret",
			rule: "IAC-503", path: "docker-compose.yml", want: 1,
			body: "services:\n  app:\n    image: app:1\n    environment:\n      - DB_PASSWORD=hunter2-prod-Passw0rd\n      - LOG_LEVEL=info\n",
		},
		{
			name: "compose list entry that forwards the variable from the host",
			rule: "IAC-503", path: "docker-compose.yml", want: 0,
			body: "services:\n  app:\n    image: app:1\n    environment:\n      - DB_PASSWORD\n      - API_TOKEN=${API_TOKEN}\n      - SECRET_KEY=${SECRET_KEY:?set SECRET_KEY}\n      - PASSWORD_FILE=/run/secrets/db\n",
		},

		// ---- 3. terraform S3 public access block switched off ------------
		{
			name: "terraform block_public_acls = false",
			rule: "IAC-504", path: "main.tf", want: 4,
			body: "resource \"aws_s3_bucket_public_access_block\" \"invoices\" {\n  bucket                  = aws_s3_bucket.invoices.id\n  block_public_acls       = false\n  block_public_policy     = false\n  ignore_public_acls      = false\n  restrict_public_buckets = false\n}\n",
		},
		{
			name: "terraform public access block fully on",
			rule: "IAC-504", path: "main.tf", want: 0,
			body: "resource \"aws_s3_bucket_public_access_block\" \"invoices\" {\n  bucket                  = aws_s3_bucket.invoices.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n",
		},
		{
			name: "terraform false on an unrelated attribute of the same name family",
			rule: "IAC-504", path: "main.tf", want: 0,
			body: "resource \"aws_s3_bucket\" \"logs\" {\n  bucket        = \"logs\"\n  force_destroy = false\n}\nresource \"aws_s3_bucket_public_access_block\" \"logs\" {\n  bucket                  = aws_s3_bucket.logs.id\n  block_public_acls       = true\n  block_public_policy     = true\n  ignore_public_acls      = true\n  restrict_public_buckets = true\n}\n",
		},

		// ---- 4. capabilities.add replacing drop: [ALL] -------------------
		{
			name: "k8s flow-style add: [SYS_ADMIN]",
			rule: "IAC-302", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            capabilities: {add: [SYS_ADMIN]}\n",
		},
		{
			name: "k8s block add whose dangerous capability is not first",
			rule: "IAC-302", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            capabilities:\n              add:\n                - NET_BIND_SERVICE\n                - NET_ADMIN\n",
		},
		{
			name: "k8s flow-style add: [ALL]",
			rule: "IAC-302", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            capabilities: {drop: [ALL], add: [ALL]}\n",
		},
		{
			name: "k8s drop ALL then add only NET_BIND_SERVICE is the documented hardening",
			rule: "IAC-302", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            capabilities:\n              drop: [ALL]\n              add: [NET_BIND_SERVICE]\n",
		},
		{
			name: "k8s block-style drop ALL alone",
			rule: "IAC-302", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            capabilities:\n              drop:\n                - ALL\n",
		},
		{
			name: "k8s flow-style add: [SYS_PTRACE]",
			rule: "IAC-028", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: debug\n          image: " + pinnedImage + "\n          securityContext:\n            capabilities: {add: [SYS_PTRACE]}\n",
		},
		{
			name: "k8s flow-style add of an ordinary capability",
			rule: "IAC-028", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            capabilities: {drop: [ALL], add: [CHOWN, NET_BIND_SERVICE]}\n",
		},

		// ---- 6. seccomp set at the POD level is inherited ---------------
		{
			name: "seccomp RuntimeDefault at pod level covers a container with its own securityContext",
			rule: "IAC-135", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      securityContext:\n        runAsNonRoot: true\n        seccompProfile: {type: RuntimeDefault}\n      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            allowPrivilegeEscalation: false\n            readOnlyRootFilesystem: true\n",
		},
		{
			name: "seccomp on every container, none at pod level",
			rule: "IAC-135", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            seccompProfile: {type: RuntimeDefault}\n        - name: sidecar\n          image: " + pinnedImage + "\n          securityContext:\n            seccompProfile: {type: RuntimeDefault}\n",
		},
		{
			name: "no seccomp anywhere: the container securityContext sets other things and no profile is inherited",
			rule: "IAC-135", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            allowPrivilegeEscalation: false\n",
		},
		{
			name: "seccomp on one container only, the sidecar has none and inherits nothing",
			rule: "IAC-135", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            seccompProfile: {type: RuntimeDefault}\n        - name: sidecar\n          image: " + pinnedImage + "\n          securityContext:\n            runAsNonRoot: true\n",
		},
		{
			name: "seccomp Unconfined is a profile that is set, and is reported by its own rule not as absent",
			rule: "IAC-135", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      securityContext:\n        seccompProfile: {type: Unconfined}\n      containers:\n        - name: app\n          image: " + pinnedImage + "\n",
		},

		{
			name: "a profile on the first Deployment does not cover the second one in the file",
			rule: "IAC-135", path: "deployments.yaml", want: 1,
			body: k8sDeploymentHead + "      securityContext:\n        seccompProfile: {type: RuntimeDefault}\n      containers:\n        - name: app\n          image: " + pinnedImage + "\n          securityContext:\n            allowPrivilegeEscalation: false\n---\n" +
				"apiVersion: apps/v1\nkind: Deployment\nmetadata:\n  name: worker\nspec:\n  template:\n    spec:\n      containers:\n        - name: worker\n          image: " + pinnedImage + "\n          securityContext:\n            allowPrivilegeEscalation: false\n",
		},
		{
			name: "a CronJob keeps the pod securityContext under jobTemplate",
			rule: "IAC-135", path: "cronjob.yaml", want: 0,
			body: "apiVersion: batch/v1\nkind: CronJob\nmetadata:\n  name: ledger\nspec:\n  schedule: \"0 * * * *\"\n  jobTemplate:\n    spec:\n      template:\n        spec:\n          securityContext:\n            seccompProfile: {type: RuntimeDefault}\n          containers:\n            - name: job\n              image: " + pinnedImage + "\n              securityContext:\n                allowPrivilegeEscalation: false\n          restartPolicy: Never\n",
		},

		// ---- 7. an Ingress with a tls block ----------------------------
		{
			name: "ingress with tls is not reported by the verify-TLS rule",
			rule: "IAC-149", path: "ingress.yaml", want: 0,
			body: "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: invoicely\nspec:\n  tls:\n    - hosts: [invoicely.example.com]\n      secretName: invoicely-tls\n  rules:\n    - host: invoicely.example.com\n",
		},
		{
			name: "ingress without tls is reported",
			rule: "IAC-149", path: "ingress.yaml", want: 1,
			body: "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: invoicely\nspec:\n  rules:\n    - host: invoicely.example.com\n",
		},

		// ---- IAC-144: the correct pattern is not the defect ------------
		{
			name: "a single key from a Secret is the recommended way to pass a credential",
			rule: "IAC-144", path: "deployment.yaml", want: 0,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          env:\n            - name: DB_PASSWORD\n              valueFrom:\n                secretKeyRef:\n                  name: invoicely-db\n                  key: password\n",
		},
		{
			name: "envFrom a whole Secret hands every key of it to the process",
			rule: "IAC-144", path: "deployment.yaml", want: 1,
			body: k8sDeploymentHead + "      containers:\n        - name: app\n          image: " + pinnedImage + "\n          envFrom:\n            - secretRef:\n                name: invoicely-all-secrets\n",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := iacFindings(t, tc.path, tc.body, tc.rule)
			if len(got) != tc.want {
				for _, f := range got {
					t.Logf("  %s line %d: %s", f.RuleID, f.Location.StartLine, f.Message)
				}
				t.Fatalf("%s fired %d times, want %d", tc.rule, len(got), tc.want)
			}
		})
	}
}

// IAC-296 used to match `kind: Ingress` and nothing else, so it fired on every
// Ingress. Its claim is now one that can be checked, and is distinct from
// IAC-149 (no tls at all): an Ingress that HAS a tls block, but where a host
// is served that no tls entry covers, or a tls entry names no certificate
// source. It never fires where IAC-149 does, and it does not guess at a Helm
// template it cannot render.
func TestFalseAllClear_IAC296ChecksTheTLSItFinds(t *testing.T) {
	head := "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: invoicely\n"
	rule := func(hosts ...string) string {
		out := "  rules:\n"
		for _, h := range hosts {
			out += "    - host: " + h + "\n      http:\n        paths:\n          - path: /\n            pathType: Prefix\n            backend: {service: {name: web, port: {number: 80}}}\n"
		}
		return out
	}
	cases := []struct {
		name string
		body string
		want int
	}{
		{"tls covers the host and names a secret", head + "spec:\n  tls:\n    - hosts: [a.example.com]\n      secretName: a-tls\n" + rule("a.example.com"), 0},
		{"a wildcard entry covers one label", head + "spec:\n  tls:\n    - hosts: [\"*.example.com\"]\n      secretName: w-tls\n" + rule("a.example.com"), 0},
		{"a wildcard does not cover two labels", head + "spec:\n  tls:\n    - hosts: [\"*.example.com\"]\n      secretName: w-tls\n" + rule("a.b.example.com"), 1},
		{"a second host no tls entry covers is served in plain text", head + "spec:\n  tls:\n    - hosts: [a.example.com]\n      secretName: a-tls\n" + rule("a.example.com", "admin.example.com"), 1},
		{"a tls entry with no hosts is the default and covers every host", head + "spec:\n  tls:\n    - secretName: any-tls\n" + rule("a.example.com"), 0},
		{"tls with no secretName and no certificate source", head + "spec:\n  tls:\n    - hosts: [a.example.com]\n" + rule("a.example.com"), 1},
		{"no secretName but cert-manager provides it", "apiVersion: networking.k8s.io/v1\nkind: Ingress\nmetadata:\n  name: invoicely\n  annotations:\n    cert-manager.io/cluster-issuer: letsencrypt\nspec:\n  tls:\n    - hosts: [a.example.com]\n" + rule("a.example.com"), 0},
		{"no tls at all is IAC-149's, not this rule's", head + "spec:\n" + rule("a.example.com"), 0},
		{"a templated host is not evaluated", head + "spec:\n  tls:\n    - hosts: [a.example.com]\n      secretName: a-tls\n  rules:\n    - host: \"{{ .Values.host }}\"\n", 0},
		{"a Helm template with a conditional tls block cannot be evaluated", "{{- if .Values.ingress.enabled -}}\n" + head + "spec:\n  {{- if .Values.ingress.tls }}\n  tls:\n    - secretName: x\n  {{- end }}\n  rules:\n    {{- range .Values.ingress.hosts }}\n    - host: {{ .host | quote }}\n    {{- end }}\n{{- end }}\n", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := iacFindings(t, "ingress.yaml", tc.body, "IAC-296")
			if len(got) != tc.want {
				t.Fatalf("IAC-296 fired %d times, want %d", len(got), tc.want)
			}
			if tc.want > 0 && len(iacFindings(t, "ingress.yaml", tc.body, "IAC-149")) != 0 {
				t.Errorf("IAC-296 and IAC-149 both fired on one Ingress")
			}
		})
	}
}
