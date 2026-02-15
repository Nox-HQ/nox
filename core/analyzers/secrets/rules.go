package secrets

import (
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// secretRule is a compact representation used to define built-in rules in a
// table. Each entry is converted to a rules.Rule by builtinSecretRules().
type secretRule struct {
	id          string
	severity    findings.Severity
	confidence  findings.Confidence
	pattern     string
	description string
	cwe         string
	keywords    []string
	remediation string
	references  []string
}

// builtinSecretRules returns all built-in secret detection rules.
func builtinSecretRules() []*rules.Rule {
	defs := []secretRule{
		// -----------------------------------------------------------------
		// Cloud Providers (SEC-001 to SEC-015)
		// -----------------------------------------------------------------
		{
			id: "SEC-001", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `\b((?:A3T[A-Z0-9]|AKIA|ASIA|ABIA|ACCA)[A-Z2-7]{16})\b`,
			description: "AWS Access Key ID detected",
			cwe:         "CWE-798", keywords: []string{"akia", "asia", "abia", "acca", "a3t"},
			remediation: "Use environment variables or AWS IAM roles instead of hard-coded keys. Rotate the exposed key immediately via the AWS console.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://docs.aws.amazon.com/IAM/latest/UserGuide/id_credentials_access-keys.html"},
		},
		{
			id: "SEC-002", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)aws_secret_access_key\s*[=:]\s*[A-Za-z0-9/+=]{40}`,
			description: "AWS Secret Access Key detected",
			cwe:         "CWE-798", keywords: []string{"aws_secret"},
			remediation: "Use environment variables or AWS Secrets Manager. Remove the key from source and rotate it immediately via the AWS console.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://docs.aws.amazon.com/secretsmanager/latest/userguide/intro.html"},
		},
		{
			id: "SEC-006", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `amzn\.mws\.[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`,
			description: "AWS MWS Key detected",
			cwe:         "CWE-798", keywords: []string{"amzn.mws"},
			remediation: "Store MWS keys in a secrets manager. Rotate the key in Amazon Seller Central.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-007", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `AIza[0-9A-Za-z\-_]{35}`,
			description: "GCP API Key detected",
			cwe:         "CWE-798", keywords: []string{"aiza"},
			remediation: "Restrict the API key in the GCP Console and use application default credentials instead.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://cloud.google.com/docs/authentication/api-keys"},
		},
		{
			id: "SEC-008", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)"type"\s*:\s*"service_account"`,
			description: "GCP Service Account JSON detected",
			cwe:         "CWE-798", keywords: []string{"service_account"},
			remediation: "Use workload identity federation instead of service account key files. Delete and rotate the key in GCP IAM.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://cloud.google.com/iam/docs/workload-identity-federation"},
		},
		{
			id: "SEC-009", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(client_secret|client-secret)\s*[=:]\s*['"][0-9a-zA-Z~._\-]{34,}['"]`,
			description: "Azure AD Client Secret detected",
			cwe:         "CWE-798", keywords: []string{"client_secret", "client-secret"},
			remediation: "Use managed identities or certificate-based authentication. Rotate the secret in Azure AD.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-010", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `dop_v1_[a-f0-9]{64}`,
			description: "DigitalOcean Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"dop_v1_"},
			remediation: "Revoke the token in the DigitalOcean control panel and use environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-011", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `doo_v1_[a-f0-9]{64}`,
			description: "DigitalOcean OAuth Token detected",
			cwe:         "CWE-798", keywords: []string{"doo_v1_"},
			remediation: "Revoke the token in the DigitalOcean control panel and use environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-012", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)heroku[a-z0-9_ .\-]*[=:]\s*[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}`,
			description: "Heroku API Key detected",
			cwe:         "CWE-798", keywords: []string{"heroku"},
			remediation: "Regenerate the API key via 'heroku authorizations:create' and store in environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-013", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `\bLTAI[A-Za-z0-9]{12,20}\b`,
			description: "Alibaba Cloud Access Key detected",
			cwe:         "CWE-798", keywords: []string{"ltai"},
			remediation: "Rotate the key in the Alibaba Cloud console and use RAM roles instead.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-014", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)ibm[a-z0-9_ .\-]*[=:]\s*[A-Za-z0-9_\-]{44}`,
			description: "IBM Cloud API Key detected",
			cwe:         "CWE-798", keywords: []string{"ibm"},
			remediation: "Rotate the API key in IBM Cloud IAM and use environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-015", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `dapi[a-f0-9]{32}`,
			description: "Databricks API Token detected",
			cwe:         "CWE-798", keywords: []string{"dapi"},
			remediation: "Revoke the token in Databricks settings and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Source Control (SEC-003, SEC-016 to SEC-022)
		// -----------------------------------------------------------------
		{
			id: "SEC-003", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `gh[pso]_[A-Za-z0-9_]{36,}`,
			description: "GitHub Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"ghp_", "ghs_", "gho_"},
			remediation: "Revoke the token at github.com/settings/tokens and generate a new one. Use GITHUB_TOKEN environment variable or GitHub Actions secrets.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/managing-your-personal-access-tokens"},
		},
		{
			id: "SEC-016", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `github_pat_[A-Za-z0-9_]{82}`,
			description: "GitHub Fine-Grained Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"github_pat_"},
			remediation: "Revoke the token at github.com/settings/tokens and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-017", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `ghu_[A-Za-z0-9_]{36,}`,
			description: "GitHub App User-to-Server Token detected",
			cwe:         "CWE-798", keywords: []string{"ghu_"},
			remediation: "Revoke the GitHub App installation and regenerate tokens.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-018", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `glpat-[A-Za-z0-9\-_]{20,}`,
			description: "GitLab Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"glpat-"},
			remediation: "Revoke the token in GitLab user settings and use CI/CD variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-019", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `glptt-[A-Za-z0-9\-_]{20,}`,
			description: "GitLab Pipeline Trigger Token detected",
			cwe:         "CWE-798", keywords: []string{"glptt-"},
			remediation: "Revoke the trigger token in GitLab CI/CD settings and rotate.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-020", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `glrt-[A-Za-z0-9\-_]{20,}`,
			description: "GitLab Runner Registration Token detected",
			cwe:         "CWE-798", keywords: []string{"glrt-"},
			remediation: "Reset the runner registration token in GitLab admin settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-021", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)bitbucket[a-z0-9_ .\-]*secret\s*[=:]\s*['"][A-Za-z0-9]{32,}['"]`,
			description: "Bitbucket Client Secret detected",
			cwe:         "CWE-798", keywords: []string{"bitbucket"},
			remediation: "Regenerate the OAuth consumer secret in Bitbucket workspace settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-022", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `bbdc-[A-Za-z0-9]{32,}`,
			description: "Bitbucket HTTP Access Token detected",
			cwe:         "CWE-798", keywords: []string{"bbdc-"},
			remediation: "Revoke the HTTP access token in Bitbucket repository settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Communication Platforms (SEC-023 to SEC-029)
		// -----------------------------------------------------------------
		{
			id: "SEC-023", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `xoxb-[0-9]{10,13}-[0-9]{10,13}-[a-zA-Z0-9]{24,}`,
			description: "Slack Bot Token detected",
			cwe:         "CWE-798", keywords: []string{"xoxb"},
			remediation: "Regenerate the bot token in Slack app settings and store in environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://api.slack.com/authentication/token-types"},
		},
		{
			id: "SEC-024", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `xoxp-[0-9]{10,13}-[0-9]{10,13}-[0-9]{10,13}-[a-f0-9]{32}`,
			description: "Slack User Token detected",
			cwe:         "CWE-798", keywords: []string{"xoxp"},
			remediation: "Regenerate the user token and use bot tokens where possible.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-025", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `https://hooks\.slack\.com/services/T[A-Z0-9]{8,}/B[A-Z0-9]{8,}/[A-Za-z0-9]{24,}`,
			description: "Slack Webhook URL detected",
			cwe:         "CWE-798", keywords: []string{"hooks.slack.com"},
			remediation: "Regenerate the webhook URL in Slack app settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-026", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(discord[a-z0-9_ .\-]*token)\s*[=:]\s*['"]?[A-Za-z0-9._\-]{59,}['"]?`,
			description: "Discord Bot Token detected",
			cwe:         "CWE-798", keywords: []string{"discord"},
			remediation: "Regenerate the bot token in the Discord developer portal.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-027", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `https://discord(?:app)?\.com/api/webhooks/[0-9]+/[A-Za-z0-9_\-]+`,
			description: "Discord Webhook URL detected",
			cwe:         "CWE-798", keywords: []string{"discord.com/api/webhooks", "discordapp.com/api/webhooks"},
			remediation: "Delete and recreate the webhook in Discord channel settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-028", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `[0-9]{8,10}:[A-Za-z0-9_-]{35}`,
			description: "Telegram Bot Token detected",
			cwe:         "CWE-798", keywords: []string{"telegram", "bot"},
			remediation: "Revoke the bot token via BotFather on Telegram and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-029", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[0-9a-f\-]+`,
			description: "Microsoft Teams Webhook URL detected",
			cwe:         "CWE-798", keywords: []string{"webhook.office.com"},
			remediation: "Delete and recreate the Teams webhook connector.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Payment Processors (SEC-030 to SEC-038)
		// -----------------------------------------------------------------
		{
			id: "SEC-030", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `(?:sk_(?:test|live)|rk_(?:test|live))_[A-Za-z0-9]{20,}`,
			description: "Stripe API Key detected",
			cwe:         "CWE-798", keywords: []string{"sk_test", "sk_live", "rk_test", "rk_live"},
			remediation: "Roll the API key in the Stripe dashboard and use environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html", "https://stripe.com/docs/keys"},
		},
		{
			id: "SEC-031", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `whsec_[A-Za-z0-9+/=]{32,}`,
			description: "Stripe Webhook Secret detected",
			cwe:         "CWE-798", keywords: []string{"whsec_"},
			remediation: "Roll the webhook signing secret in the Stripe dashboard.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-032", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sq0atp-[A-Za-z0-9\-_]{22,}`,
			description: "Square Access Token detected",
			cwe:         "CWE-798", keywords: []string{"sq0atp-"},
			remediation: "Rotate the token in the Square Developer Dashboard.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-033", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sq0csp-[A-Za-z0-9\-_]{43,}`,
			description: "Square OAuth Secret detected",
			cwe:         "CWE-798", keywords: []string{"sq0csp-"},
			remediation: "Rotate the OAuth secret in the Square Developer Dashboard.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-034", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `shpss_[a-fA-F0-9]{32}`,
			description: "Shopify Shared Secret detected",
			cwe:         "CWE-798", keywords: []string{"shpss_"},
			remediation: "Rotate the shared secret in Shopify app settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-035", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `shpat_[a-fA-F0-9]{32}`,
			description: "Shopify Access Token detected",
			cwe:         "CWE-798", keywords: []string{"shpat_"},
			remediation: "Revoke the access token in Shopify admin and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-036", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `shpca_[a-fA-F0-9]{32}`,
			description: "Shopify Custom App Token detected",
			cwe:         "CWE-798", keywords: []string{"shpca_"},
			remediation: "Revoke and regenerate the custom app token in Shopify admin.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-037", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `shppa_[a-fA-F0-9]{32}`,
			description: "Shopify Private App Token detected",
			cwe:         "CWE-798", keywords: []string{"shppa_"},
			remediation: "Revoke and regenerate the private app token in Shopify admin.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-038", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}`,
			description: "PayPal Braintree Access Token detected",
			cwe:         "CWE-798", keywords: []string{"access_token$production$"},
			remediation: "Revoke the access token in the Braintree control panel.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// AI/ML Providers (SEC-039 to SEC-044)
		// -----------------------------------------------------------------
		{
			id: "SEC-039", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}`,
			description: "OpenAI API Key detected",
			cwe:         "CWE-798", keywords: []string{"sk-", "t3blbkfj"},
			remediation: "Revoke the key at platform.openai.com/api-keys and generate a new one. Use environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-040", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sk-proj-[A-Za-z0-9\-_]{80,}`,
			description: "OpenAI Project API Key detected",
			cwe:         "CWE-798", keywords: []string{"sk-proj-"},
			remediation: "Revoke the key at platform.openai.com/api-keys and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-041", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sk-ant-api[a-zA-Z0-9\-_]{80,}`,
			description: "Anthropic API Key detected",
			cwe:         "CWE-798", keywords: []string{"sk-ant-api"},
			remediation: "Revoke the key in the Anthropic Console and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-042", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `hf_[A-Za-z0-9]{34,}`,
			description: "HuggingFace Token detected",
			cwe:         "CWE-798", keywords: []string{"hf_"},
			remediation: "Revoke the token in HuggingFace account settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-043", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `r8_[A-Za-z0-9]{38,}`,
			description: "Replicate API Token detected",
			cwe:         "CWE-798", keywords: []string{"r8_"},
			remediation: "Regenerate the token in Replicate account settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-044", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)cohere[a-z0-9_ .\-]*[=:]\s*['"]?[A-Za-z0-9]{40}['"]?`,
			description: "Cohere API Key detected",
			cwe:         "CWE-798", keywords: []string{"cohere"},
			remediation: "Regenerate the API key in the Cohere dashboard.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// DevOps & CI/CD (SEC-045 to SEC-056)
		// -----------------------------------------------------------------
		{
			id: "SEC-045", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `npm_[A-Za-z0-9]{36,}`,
			description: "NPM Access Token detected",
			cwe:         "CWE-798", keywords: []string{"npm_"},
			remediation: "Revoke the token on npmjs.com and generate a new one. Use npm automation tokens in CI.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-046", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `pypi-[A-Za-z0-9\-_]{16,}`,
			description: "PyPI Upload Token detected",
			cwe:         "CWE-798", keywords: []string{"pypi-"},
			remediation: "Revoke the token on pypi.org and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-047", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `rubygems_[a-f0-9]{48}`,
			description: "RubyGems API Token detected",
			cwe:         "CWE-798", keywords: []string{"rubygems_"},
			remediation: "Revoke the token on rubygems.org and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-048", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `oy2[A-Za-z0-9]{43}`,
			description: "NuGet API Key detected",
			cwe:         "CWE-798", keywords: []string{"oy2"},
			remediation: "Regenerate the API key on nuget.org.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-049", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `dckr_pat_[A-Za-z0-9\-_]{27,}`,
			description: "Docker Hub Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"dckr_pat_"},
			remediation: "Revoke the token in Docker Hub security settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-050", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `[a-zA-Z0-9]{14}\.atlasv1\.[a-zA-Z0-9\-_]{60,}`,
			description: "Terraform Cloud/Enterprise API Token detected",
			cwe:         "CWE-798", keywords: []string{"atlasv1"},
			remediation: "Regenerate the token in Terraform Cloud settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-051", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `hvs\.[A-Za-z0-9]{24,}`,
			description: "HashiCorp Vault Service Token detected",
			cwe:         "CWE-798", keywords: []string{"hvs."},
			remediation: "Revoke the token using 'vault token revoke' and issue a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-052", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `hvb\.[A-Za-z0-9]{24,}`,
			description: "HashiCorp Vault Batch Token detected",
			cwe:         "CWE-798", keywords: []string{"hvb."},
			remediation: "Revoke the batch token and issue a new one from Vault.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-053", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)fastly[a-z0-9_ .\-]*[=:]\s*['"]?[A-Za-z0-9\-_]{32}['"]?`,
			description: "Fastly API Key detected",
			cwe:         "CWE-798", keywords: []string{"fastly"},
			remediation: "Regenerate the API token in Fastly account settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-054", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `dp\.pt\.[A-Za-z0-9]{43,}`,
			description: "Doppler API Token detected",
			cwe:         "CWE-798", keywords: []string{"dp.pt."},
			remediation: "Revoke the token in Doppler and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-055", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `cio[a-zA-Z0-9]{36,}`,
			description: "Cargo Registry Token detected",
			cwe:         "CWE-798", keywords: []string{"cio"},
			remediation: "Revoke the token on crates.io and generate a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-056", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `glc_[A-Za-z0-9+/=]{32,}`,
			description: "Grafana Cloud Token detected",
			cwe:         "CWE-798", keywords: []string{"glc_"},
			remediation: "Regenerate the token in Grafana Cloud settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// SaaS & APIs (SEC-057 to SEC-072)
		// -----------------------------------------------------------------
		{
			id: "SEC-057", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `SK[0-9a-fA-F]{32}`,
			description: "Twilio API Key detected",
			cwe:         "CWE-798", keywords: []string{"twilio", "sk"},
			remediation: "Delete and regenerate the API key in the Twilio console.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-058", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`,
			description: "SendGrid API Key detected",
			cwe:         "CWE-798", keywords: []string{"sg."},
			remediation: "Delete and recreate the API key in SendGrid settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-059", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `[a-f0-9]{32}-us[0-9]{1,2}`,
			description: "Mailchimp API Key detected",
			cwe:         "CWE-798", keywords: []string{"-us"},
			remediation: "Regenerate the API key in Mailchimp account settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-060", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(mailgun[a-z0-9_ .\-]*key)\s*[=:]\s*['"]?key-[a-f0-9]{32}['"]?`,
			description: "Mailgun API Key detected",
			cwe:         "CWE-798", keywords: []string{"mailgun"},
			remediation: "Rotate the API key in Mailgun domain settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-061", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(datadog[a-z0-9_ .\-]*key)\s*[=:]\s*['"]?[a-f0-9]{32,40}['"]?`,
			description: "Datadog API Key detected",
			cwe:         "CWE-798", keywords: []string{"datadog"},
			remediation: "Rotate the API key in Datadog organization settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-062", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `NRAK-[A-Z0-9]{27}`,
			description: "New Relic API Key detected",
			cwe:         "CWE-798", keywords: []string{"nrak-"},
			remediation: "Delete and regenerate the key in New Relic API key management.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-063", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(pagerduty[a-z0-9_ .\-]*key)\s*[=:]\s*['"]?[A-Za-z0-9+/]{20,}['"]?`,
			description: "PagerDuty API Key detected",
			cwe:         "CWE-798", keywords: []string{"pagerduty"},
			remediation: "Regenerate the API key in PagerDuty account settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-064", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(airtable[a-z0-9_ .\-]*key)\s*[=:]\s*['"]?key[A-Za-z0-9]{14}['"]?`,
			description: "Airtable API Key detected",
			cwe:         "CWE-798", keywords: []string{"airtable"},
			remediation: "Regenerate the API key in Airtable account settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-065", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(algolia[a-z0-9_ .\-]*key)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?`,
			description: "Algolia API Key detected",
			cwe:         "CWE-798", keywords: []string{"algolia"},
			remediation: "Rotate the API key in Algolia dashboard.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-066", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `lin_api_[A-Za-z0-9]{40,}`,
			description: "Linear API Key detected",
			cwe:         "CWE-798", keywords: []string{"lin_api_"},
			remediation: "Revoke the API key in Linear settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-067", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `PMAK-[A-Za-z0-9]{24}-[A-Za-z0-9]{34}`,
			description: "Postman API Key detected",
			cwe:         "CWE-798", keywords: []string{"pmak-"},
			remediation: "Regenerate the API key in Postman account settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-068", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(okta[a-z0-9_ .\-]*token)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{42}['"]?`,
			description: "Okta API Token detected",
			cwe:         "CWE-798", keywords: []string{"okta"},
			remediation: "Revoke the token in Okta admin console and create a new one.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-069", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(contentful[a-z0-9_ .\-]*token)\s*[=:]\s*['"]?[A-Za-z0-9\-_]{43,}['"]?`,
			description: "Contentful Delivery Token detected",
			cwe:         "CWE-798", keywords: []string{"contentful"},
			remediation: "Rotate the token in Contentful space settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-070", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?:live|test)_[a-f0-9]{32,}`,
			description: "Lob API Key detected",
			cwe:         "CWE-798", keywords: []string{"live_", "test_", "lob"},
			remediation: "Rotate the API key in Lob dashboard settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-071", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sbp_[a-f0-9]{40}`,
			description: "Supabase API Key detected",
			cwe:         "CWE-798", keywords: []string{"sbp_"},
			remediation: "Rotate the key in Supabase project settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-072", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(confluent[a-z0-9_ .\-]*key)\s*[=:]\s*['"]?[A-Za-z0-9]{16,}['"]?`,
			description: "Confluent API Key/Secret detected",
			cwe:         "CWE-798", keywords: []string{"confluent"},
			remediation: "Rotate the API key in Confluent Cloud settings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Database & Infrastructure (SEC-073 to SEC-076)
		// -----------------------------------------------------------------
		{
			id: "SEC-073", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(mysql|postgres(?:ql)?|mssql|sqlserver|oracle|mariadb)://[^:\n]+:[^@\n]+@[^\s'"]+`,
			description: "Database Connection String with credentials detected",
			cwe:         "CWE-798", keywords: []string{"://"},
			remediation: "Use environment variables or a secrets manager for database connection strings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-074", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `mongodb\+srv://[^:\n]+:[^@\n]+@[^\s'"]+`,
			description: "MongoDB SRV Connection String with credentials detected",
			cwe:         "CWE-798", keywords: []string{"mongodb+srv://"},
			remediation: "Use environment variables for MongoDB connection strings. Rotate the database password.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-075", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(firebase[a-z0-9_ .\-]*key)\s*[=:]\s*['"]?AIza[0-9A-Za-z\-_]{35}['"]?`,
			description: "Firebase API Key detected",
			cwe:         "CWE-798", keywords: []string{"firebase"},
			remediation: "Restrict the API key in Firebase console. Use App Check for additional security.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-076", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `rediss?://[^:\n]+:[^@\n]+@[^\s'"]+`,
			description: "Redis URL with password detected",
			cwe:         "CWE-798", keywords: []string{"redis://", "rediss://"},
			remediation: "Use environment variables for Redis connection strings. Rotate the password.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Crypto & Keys (SEC-004, SEC-077 to SEC-079)
		// -----------------------------------------------------------------
		{
			id: "SEC-004", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY-----`,
			description: "Private key header detected",
			cwe:         "CWE-321", keywords: []string{"-----begin"},
			remediation: "Remove the private key from source control. Store keys in a secrets manager or use encrypted key storage. Regenerate the key pair if it was committed.",
			references:  []string{"https://cwe.mitre.org/data/definitions/321.html"},
		},
		{
			id: "SEC-077", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `AGE-SECRET-KEY-1[QPZRY9X8GF2TVDW0S3JN54KHCE6MUA7L]{58}`,
			description: "Age secret key detected",
			cwe:         "CWE-321", keywords: []string{"age-secret-key"},
			remediation: "Remove the secret key from source and regenerate with 'age-keygen'.",
			references:  []string{"https://cwe.mitre.org/data/definitions/321.html"},
		},
		{
			id: "SEC-078", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			// nox:ignore SEC-078 -- rule definition, not a real finding
			pattern:     `(?i)-----BEGIN PGP PRIVATE KEY BLOCK-----`,
			description: "PGP Private Key Block detected",
			cwe:         "CWE-321", keywords: []string{"pgp private key"},
			remediation: "Remove the PGP private key from source control. Revoke and regenerate the key pair.",
			references:  []string{"https://cwe.mitre.org/data/definitions/321.html"},
		},
		{
			id: "SEC-079", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(password|passphrase|pass)\s*[=:]\s*['"][^'"]{4,}['"]\s*.*\.(p12|pfx)`,
			description: "PKCS12/PFX file password reference detected",
			cwe:         "CWE-321", keywords: []string{".p12", ".pfx"},
			remediation: "Store PKCS12/PFX passwords in a secrets manager, not in source code.",
			references:  []string{"https://cwe.mitre.org/data/definitions/321.html"},
		},

		// -----------------------------------------------------------------
		// Generic Patterns (SEC-005, SEC-080 to SEC-086)
		// -----------------------------------------------------------------
		{
			id: "SEC-005", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(api[_-]?key|apikey|api[_-]?secret)\s*[=:]\s*['"][A-Za-z0-9]{16,}['"]`,
			description: "Generic API key assignment detected",
			cwe:         "CWE-798", keywords: []string{"api_key", "apikey", "api-key", "api_secret", "api-secret"},
			remediation: "Move API keys to environment variables or a secrets manager. Avoid committing credentials to version control.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-080", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(password|passwd|pwd)\s*[=:]\s*['"][^'"]{8,}['"]`,
			description: "Generic password assignment detected",
			cwe:         "CWE-798", keywords: []string{"password", "passwd", "pwd"},
			remediation: "Use environment variables or a secrets manager for passwords.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-081", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(secret|credential)[_-]?\s*[=:]\s*['"][A-Za-z0-9+/=]{16,}['"]`,
			description: "Generic secret assignment detected",
			cwe:         "CWE-798", keywords: []string{"secret", "credential"},
			remediation: "Use environment variables or a secrets manager for secrets and credentials.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-082", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(authorization|auth)\s*[=:]\s*['"]?Bearer\s+[A-Za-z0-9\-_.~+/]+=*['"]?`,
			description: "Bearer token detected",
			cwe:         "CWE-798", keywords: []string{"bearer"},
			remediation: "Do not hard-code bearer tokens. Use environment variables or a token refresh mechanism.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-083", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:     `(?i)(authorization|auth)\s*[=:]\s*['"]?Basic\s+[A-Za-z0-9+/=]{10,}['"]?`,
			description: "Basic auth header detected",
			cwe:         "CWE-798", keywords: []string{"basic"},
			remediation: "Do not hard-code Basic auth credentials. Use environment variables or a credentials provider.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-084", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:     `eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`,
			description: "JWT token detected",
			cwe:         "CWE-798", keywords: []string{"eyj"},
			remediation: "Do not hard-code JWT tokens. Use a proper authentication flow.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-085", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `https?://[^:\n]+:[^@\n]+@[^\s'"]{3,}`,
			description: "URL with embedded password detected",
			cwe:         "CWE-798", keywords: []string{"://"},
			remediation: "Remove credentials from URLs. Use environment variables or a credentials provider.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-086", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(db_pass(?:word)?|database_password)\s*[=:]\s*['"][^'"]{4,}['"]`,
			description: "Hardcoded database password detected",
			cwe:         "CWE-798", keywords: []string{"db_pass", "database_password"},
			remediation: "Use environment variables or a secrets manager for database passwords.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Cloud/Infra (SEC-087 to SEC-100)
		// -----------------------------------------------------------------
		{
			id: "SEC-087", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)cloudflare[_-]?api[_-]?token\s*[=:]\s*['"]?[A-Za-z0-9_-]{40}`,
			description: "Cloudflare API Token detected",
			cwe:         "CWE-798", keywords: []string{"cloudflare_api_token", "cloudflare-api-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-088", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(x-auth-key|cloudflare[_-]?api[_-]?key)\s*[=:]\s*['"]?[a-f0-9]{37}['"]?`,
			description: "Cloudflare API Key detected",
			cwe:         "CWE-798", keywords: []string{"x-auth-key", "cloudflare_api_key", "cloudflare-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-089", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `fo1_[A-Za-z0-9_-]{40,}`,
			description: "Fly.io Access Token detected",
			cwe:         "CWE-798", keywords: []string{"fo1_"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-090", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(vercel[_-]?token|VERCEL_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9]{24,}['"]?`,
			description: "Vercel Token detected",
			cwe:         "CWE-798", keywords: []string{"vercel_token", "vercel-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-091", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(netlify[_-]?token|NETLIFY_AUTH_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9_-]{40,}['"]?`,
			description: "Netlify Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"netlify_token", "netlify-token", "netlify_auth_token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-092", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `pscale_tkn_[A-Za-z0-9_-]{32,}`,
			description: "PlanetScale Token detected",
			cwe:         "CWE-798", keywords: []string{"pscale_tkn_"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-093", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `pscale_oauth_[A-Za-z0-9_-]{32,}`,
			description: "PlanetScale OAuth Token detected",
			cwe:         "CWE-798", keywords: []string{"pscale_oauth_"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-094", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `pul-[a-f0-9]{40}`,
			description: "Pulumi Access Token detected",
			cwe:         "CWE-798", keywords: []string{"pul-"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-095", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(snowflake[_-]?password|sf[_-]?password)\s*[=:]\s*['"][^'"]{6,}['"]`,
			description: "Snowflake Key Pair password detected",
			cwe:         "CWE-798", keywords: []string{"snowflake_password", "snowflake-password", "sf_password", "sf-password"},
			remediation: "Rotate the exposed password immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-096", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(mongodb[_-]?api[_-]?key|MONGO_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?`,
			description: "MongoDB Atlas API Key detected",
			cwe:         "CWE-798", keywords: []string{"mongodb_api_key", "mongodb-api-key", "mongo_api_key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-097", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(aiven[_-]?token|AIVEN_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9]{48,}['"]?`,
			description: "Aiven Token detected",
			cwe:         "CWE-798", keywords: []string{"aiven_token", "aiven-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-098", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `rnd_[A-Za-z0-9]{32,}`,
			description: "Render API Key detected",
			cwe:         "CWE-798", keywords: []string{"rnd_"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-099", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(railway[_-]?token|RAILWAY_TOKEN)\s*[=:]\s*['"]?[a-f0-9-]{36,}['"]?`,
			description: "Railway Token detected",
			cwe:         "CWE-798", keywords: []string{"railway_token", "railway-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-100", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(supabase[_-]?service[_-]?role[_-]?key|SUPABASE_SERVICE_ROLE_KEY)\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{100,}['"]?`,
			description: "Supabase Service Role Key detected",
			cwe:         "CWE-798", keywords: []string{"supabase_service_role_key", "supabase-service-role-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Identity/Auth (SEC-101 to SEC-106)
		// -----------------------------------------------------------------
		{
			id: "SEC-101", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(auth0[_-]?management[_-]?token|AUTH0_TOKEN)\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{50,}['"]?`,
			description: "Auth0 Management API Token detected",
			cwe:         "CWE-798", keywords: []string{"auth0_management_token", "auth0-management-token", "auth0_token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-102", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(okta[_-]?api[_-]?token|OKTA_TOKEN)\s*[=:]\s*['"]?00[A-Za-z0-9_-]{40,}['"]?`,
			description: "Okta API Token detected",
			cwe:         "CWE-798", keywords: []string{"okta_api_token", "okta-api-token", "okta_token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-103", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sk_(live|test)_[A-Za-z0-9]{24,}`,
			description: "Clerk Secret Key detected",
			cwe:         "CWE-798", keywords: []string{"sk_live_", "sk_test_"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-104", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `(?i)"type"\s*:\s*"service_account"[^}]*"project_id"\s*:\s*"[^"]*firebase`,
			description: "Firebase Service Account detected",
			cwe:         "CWE-798", keywords: []string{"service_account", "firebase"},
			remediation: "Remove the service account JSON from source control. Use workload identity or environment variables.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-105", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(supabase[_-]?anon[_-]?key|SUPABASE_ANON_KEY)\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{100,}['"]?`,
			description: "Supabase Anon Key detected",
			cwe:         "CWE-798", keywords: []string{"supabase_anon_key", "supabase-anon-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-106", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(keycloak[_-]?client[_-]?secret|KEYCLOAK_SECRET)\s*[=:]\s*['"]?[a-f0-9-]{36}['"]?`,
			description: "Keycloak Client Secret detected",
			cwe:         "CWE-798", keywords: []string{"keycloak_client_secret", "keycloak-client-secret", "keycloak_secret"},
			remediation: "Rotate the exposed secret immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Observability (SEC-107 to SEC-112)
		// -----------------------------------------------------------------
		{
			id: "SEC-107", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(datadog[_-]?api[_-]?key|DD_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?`,
			description: "Datadog API Key detected",
			cwe:         "CWE-798", keywords: []string{"datadog_api_key", "datadog-api-key", "dd_api_key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-108", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(datadog[_-]?app[_-]?key|DD_APP_KEY)\s*[=:]\s*['"]?[a-f0-9]{40}['"]?`,
			description: "Datadog App Key detected",
			cwe:         "CWE-798", keywords: []string{"datadog_app_key", "datadog-app-key", "dd_app_key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-109", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `https?://[a-f0-9]{32}@[a-z0-9.]+\.ingest\.sentry\.io/[0-9]+`,
			description: "Sentry DSN detected",
			cwe:         "CWE-798", keywords: []string{"sentry.io", "ingest.sentry"},
			remediation: "Rotate the exposed DSN immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-110", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(elastic[_-]?api[_-]?key|ELASTIC_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9_-]{40,}['"]?`,
			description: "Elastic API Key detected",
			cwe:         "CWE-798", keywords: []string{"elastic_api_key", "elastic-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-111", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(splunk[_-]?hec[_-]?token|SPLUNK_TOKEN)\s*[=:]\s*['"]?[a-f0-9-]{36}['"]?`,
			description: "Splunk HEC Token detected",
			cwe:         "CWE-798", keywords: []string{"splunk_hec_token", "splunk-hec-token", "splunk_token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-112", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(grafana[_-]?api[_-]?key|GF_API_KEY)\s*[=:]\s*['"]?eyJ[A-Za-z0-9_-]{30,}['"]?`,
			description: "Grafana API Key detected",
			cwe:         "CWE-798", keywords: []string{"grafana_api_key", "grafana-api-key", "gf_api_key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// AI/ML (SEC-113 to SEC-122)
		// -----------------------------------------------------------------
		{
			id: "SEC-113", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(pinecone[_-]?api[_-]?key|PINECONE_API_KEY)\s*[=:]\s*['"]?[a-f0-9-]{36}['"]?`,
			description: "Pinecone API Key detected",
			cwe:         "CWE-798", keywords: []string{"pinecone_api_key", "pinecone-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-114", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(weaviate[_-]?api[_-]?key|WEAVIATE_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9]{32,}['"]?`,
			description: "Weaviate API Key detected",
			cwe:         "CWE-798", keywords: []string{"weaviate_api_key", "weaviate-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-115", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `AIza[0-9A-Za-z\-_]{35}`,
			description: "Gemini / GCP API key detected",
			cwe:         "CWE-798", keywords: []string{"aiza"},
			remediation: "Rotate the exposed key immediately. Restrict the API key in the GCP Console.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-116", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(mistral[_-]?api[_-]?key|MISTRAL_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9]{32,}['"]?`,
			description: "Mistral API Key detected",
			cwe:         "CWE-798", keywords: []string{"mistral_api_key", "mistral-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-117", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `gsk_[A-Za-z0-9]{48,}`,
			description: "Groq API Key detected",
			cwe:         "CWE-798", keywords: []string{"gsk_"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-118", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(together[_-]?api[_-]?key|TOGETHER_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{64}['"]?`,
			description: "Together AI API Key detected",
			cwe:         "CWE-798", keywords: []string{"together_api_key", "together-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-119", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `pplx-[a-f0-9]{48}`,
			description: "Perplexity API Key detected",
			cwe:         "CWE-798", keywords: []string{"pplx-"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-120", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(voyage[_-]?api[_-]?key|VOYAGE_API_KEY)\s*[=:]\s*['"]?pa-[A-Za-z0-9_-]{40,}['"]?`,
			description: "Voyage AI API Key detected",
			cwe:         "CWE-798", keywords: []string{"voyage_api_key", "voyage-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-121", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(anyscale[_-]?api[_-]?key|ANYSCALE_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9_-]{40,}['"]?`,
			description: "Anyscale API Key detected",
			cwe:         "CWE-798", keywords: []string{"anyscale_api_key", "anyscale-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-122", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(cohere[_-]?api[_-]?key|CO_API_KEY|COHERE_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9]{40}['"]?`,
			description: "Cohere API Key detected",
			cwe:         "CWE-798", keywords: []string{"cohere_api_key", "cohere-api-key", "co_api_key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Productivity/SaaS (SEC-123 to SEC-135)
		// -----------------------------------------------------------------
		{
			id: "SEC-123", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(secret_|ntn_)[A-Za-z0-9]{43}`,
			description: "Notion Internal Integration Token detected",
			cwe:         "CWE-798", keywords: []string{"secret_", "ntn_"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-124", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `figd_[A-Za-z0-9_-]{40,}`,
			description: "Figma Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"figd_"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-125", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(atlassian[_-]?api[_-]?token|ATLASSIAN_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9]{24}['"]?`,
			description: "Atlassian API Token detected",
			cwe:         "CWE-798", keywords: []string{"atlassian_api_token", "atlassian-api-token", "atlassian_token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-126", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)circle[_-]?token\s*[=:]\s*['"]?[a-f0-9]{40}['"]?`,
			description: "CircleCI Personal API Token detected",
			cwe:         "CWE-798", keywords: []string{"circle_token", "circle-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-127", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `lin_api_[A-Za-z0-9]{40}`,
			description: "Linear API Key detected",
			cwe:         "CWE-798", keywords: []string{"lin_api_"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-128", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(buildkite[_-]?agent[_-]?token|BUILDKITE_AGENT_TOKEN)\s*[=:]\s*['"]?[a-f0-9]{40,}['"]?`,
			description: "Buildkite Agent Token detected",
			cwe:         "CWE-798", keywords: []string{"buildkite_agent_token", "buildkite-agent-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-129", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(asana[_-]?token|ASANA_PAT)\s*[=:]\s*['"]?[0-9]/[0-9]{16}/[A-Za-z0-9:_-]{30,}['"]?`,
			description: "Asana Personal Access Token detected",
			cwe:         "CWE-798", keywords: []string{"asana_token", "asana-token", "asana_pat"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-130", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(airtable[_-]?api[_-]?key|AIRTABLE_API_KEY)\s*[=:]\s*['"]?key[A-Za-z0-9]{14}['"]?`,
			description: "Airtable API Key detected",
			cwe:         "CWE-798", keywords: []string{"airtable_api_key", "airtable-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-131", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(confluence[_-]?token|CONFLUENCE_API_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9]{24}['"]?`,
			description: "Confluence API Token detected",
			cwe:         "CWE-798", keywords: []string{"confluence_token", "confluence-token", "confluence_api_token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-132", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `glpat-[A-Za-z0-9_-]{20}|gldt-[A-Za-z0-9_-]{20}`,
			description: "GitLab Personal/Deploy Token detected",
			cwe:         "CWE-798", keywords: []string{"glpat-", "gldt-"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-133", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(bitbucket[_-]?app[_-]?password|BITBUCKET_PASSWORD)\s*[=:]\s*['"]?[A-Za-z0-9]{18,}['"]?`,
			description: "Bitbucket App Password detected",
			cwe:         "CWE-798", keywords: []string{"bitbucket_app_password", "bitbucket-app-password", "bitbucket_password"},
			remediation: "Rotate the exposed password immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-134", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(travis[_-]?token|TRAVIS_TOKEN)\s*[=:]\s*['"]?[A-Za-z0-9_-]{22}['"]?`,
			description: "Travis CI Token detected",
			cwe:         "CWE-798", keywords: []string{"travis_token", "travis-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-135", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(snyk[_-]?token|SNYK_TOKEN)\s*[=:]\s*['"]?[a-f0-9-]{36}['"]?`,
			description: "Snyk Token detected",
			cwe:         "CWE-798", keywords: []string{"snyk_token", "snyk-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Financial/Crypto (SEC-136 to SEC-145)
		// -----------------------------------------------------------------
		{
			id: "SEC-136", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(plaid[_-]?secret|PLAID_SECRET)\s*[=:]\s*['"]?[a-f0-9]{30}['"]?`,
			description: "Plaid Client Secret detected",
			cwe:         "CWE-798", keywords: []string{"plaid_secret", "plaid-secret"},
			remediation: "Rotate the exposed secret immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-137", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(coinbase[_-]?api[_-]?key|COINBASE_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9]{16,}['"]?`,
			description: "Coinbase API Key detected",
			cwe:         "CWE-798", keywords: []string{"coinbase_api_key", "coinbase-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-138", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(binance[_-]?api[_-]?key|BINANCE_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9]{64}['"]?`,
			description: "Binance API Key detected",
			cwe:         "CWE-798", keywords: []string{"binance_api_key", "binance-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-139", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(paypal[_-]?client[_-]?secret|PAYPAL_SECRET)\s*[=:]\s*['"]?[A-Za-z0-9_-]{40,}['"]?`,
			description: "PayPal Client Secret detected",
			cwe:         "CWE-798", keywords: []string{"paypal_client_secret", "paypal-client-secret", "paypal_secret"},
			remediation: "Rotate the exposed secret immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-140", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(adyen[_-]?api[_-]?key|ADYEN_API_KEY)\s*[=:]\s*['"]?AQE[a-z0-9]{5,}\.[A-Za-z0-9_-]{30,}['"]?`,
			description: "Adyen API Key detected",
			cwe:         "CWE-798", keywords: []string{"adyen_api_key", "adyen-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-141", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(recurly[_-]?api[_-]?key|RECURLY_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?`,
			description: "Recurly API Key detected",
			cwe:         "CWE-798", keywords: []string{"recurly_api_key", "recurly-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-142", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `access_token\$production\$[a-z0-9]{16}\$[a-f0-9]{32}`,
			description: "Braintree Access Token detected",
			cwe:         "CWE-798", keywords: []string{"access_token$production$"},
			remediation: "Revoke the access token in the Braintree control panel immediately.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-143", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sq0atp-[A-Za-z0-9_-]{22}|sq0csp-[A-Za-z0-9_-]{43}|EAAAE[A-Za-z0-9_-]{50,}`,
			description: "Square Access Token detected",
			cwe:         "CWE-798", keywords: []string{"sq0atp-", "sq0csp-", "eaaae"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-144", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(etherscan[_-]?api[_-]?key|ETHERSCAN_API_KEY)\s*[=:]\s*['"]?[A-Z0-9]{34}['"]?`,
			description: "Etherscan API Key detected",
			cwe:         "CWE-798", keywords: []string{"etherscan_api_key", "etherscan-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-145", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(alchemy[_-]?api[_-]?key|ALCHEMY_API_KEY)\s*[=:]\s*['"]?[A-Za-z0-9_-]{32}['"]?`,
			description: "Alchemy API Key detected",
			cwe:         "CWE-798", keywords: []string{"alchemy_api_key", "alchemy-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Messaging/Email (SEC-146 to SEC-155)
		// -----------------------------------------------------------------
		{
			id: "SEC-146", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(postmark[_-]?server[_-]?token|POSTMARK_TOKEN)\s*[=:]\s*['"]?[a-f0-9-]{36}['"]?`,
			description: "Postmark Server Token detected",
			cwe:         "CWE-798", keywords: []string{"postmark_server_token", "postmark-server-token", "postmark_token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-147", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `re_[A-Za-z0-9]{32,}`,
			description: "Resend API Key detected",
			cwe:         "CWE-798", keywords: []string{"re_"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-148", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(pusher[_-]?secret|PUSHER_SECRET)\s*[=:]\s*['"]?[a-f0-9]{20}['"]?`,
			description: "Pusher Secret detected",
			cwe:         "CWE-798", keywords: []string{"pusher_secret", "pusher-secret"},
			remediation: "Rotate the exposed secret immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-149", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}:[A-Za-z0-9_-]{20,}`,
			description: "Ably API Key detected",
			cwe:         "CWE-798", keywords: []string{"ably"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-150", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(messagebird[_-]?api[_-]?key|MESSAGEBIRD_KEY)\s*[=:]\s*['"]?[A-Za-z0-9]{25}['"]?`,
			description: "MessageBird API Key detected",
			cwe:         "CWE-798", keywords: []string{"messagebird_api_key", "messagebird-api-key", "messagebird_key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-151", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(nexmo[_-]?api[_-]?secret|VONAGE_SECRET)\s*[=:]\s*['"]?[a-f0-9]{16}['"]?`,
			description: "Vonage/Nexmo API Secret detected",
			cwe:         "CWE-798", keywords: []string{"nexmo_api_secret", "nexmo-api-secret", "vonage_secret"},
			remediation: "Rotate the exposed secret immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-152", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `[a-f0-9]{32}-us[0-9]{1,2}`,
			description: "Mailchimp API Key detected",
			cwe:         "CWE-798", keywords: []string{"mailchimp", "-us"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-153", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`,
			description: "SendGrid API key (legacy pattern) detected",
			cwe:         "CWE-798", keywords: []string{"sg."},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-154", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(twilio[_-]?auth[_-]?token|TWILIO_AUTH_TOKEN)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?`,
			description: "Twilio Auth Token detected",
			cwe:         "CWE-798", keywords: []string{"twilio_auth_token", "twilio-auth-token"},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-155", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(courier[_-]?api[_-]?key|COURIER_AUTH_TOKEN)\s*[=:]\s*['"]?pk_(live|test)_[A-Za-z0-9]{20,}['"]?`,
			description: "Courier API Key detected",
			cwe:         "CWE-798", keywords: []string{"courier_api_key", "courier-api-key", "courier_auth_token"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Misc (SEC-156 to SEC-160)
		// -----------------------------------------------------------------
		{
			id: "SEC-156", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `(pk|sk)\.[A-Za-z0-9]{60,}`,
			description: "Mapbox Access Token detected",
			cwe:         "CWE-798", keywords: []string{"mapbox", "pk.", "sk."},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-157", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `sdk-[a-f0-9-]{36}`,
			description: "LaunchDarkly SDK Key detected",
			cwe:         "CWE-798", keywords: []string{"sdk-", "launchdarkly"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-158", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(segment[_-]?write[_-]?key|SEGMENT_WRITE_KEY)\s*[=:]\s*['"]?[A-Za-z0-9]{32}['"]?`,
			description: "Segment Write Key detected",
			cwe:         "CWE-798", keywords: []string{"segment_write_key", "segment-write-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-159", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(amplitude[_-]?api[_-]?key|AMPLITUDE_API_KEY)\s*[=:]\s*['"]?[a-f0-9]{32}['"]?`,
			description: "Amplitude API Key detected",
			cwe:         "CWE-798", keywords: []string{"amplitude_api_key", "amplitude-api-key"},
			remediation: "Rotate the exposed key immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-160", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:     `dp\.st\.[a-zA-Z0-9_-]{2,}\.[A-Za-z0-9]{40,}`,
			description: "Doppler Token detected",
			cwe:         "CWE-798", keywords: []string{"dp.st."},
			remediation: "Rotate the exposed token immediately. Use environment variables or a secrets manager.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Gitleaks Import (SEC-164 to SEC-355) - 191 rules
		// -----------------------------------------------------------------

		{
			id: "SEC-164", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(pat[[:alnum:]]{14}\.[a-f0-9]{64})\b`,
			description: "Uncovered a possible Airtable Personal AccessToken, potentially compromising database access and leading to data leakage or alteration.",
			cwe:         "CWE-798", keywords: []string{"airtable"},
			remediation: "Imported from Gitleaks: airtable-personnal-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-165", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:algolia)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified an Algolia API Key, which could result in unauthorized search operations and data exposure on Algolia-managed platforms.",
			cwe:         "CWE-798", keywords: []string{"algolia"},
			remediation: "Imported from Gitleaks: algolia-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-166", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(sk-ant-admin01-[a-zA-Z0-9_\-]{93}AA)(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected an Anthropic Admin API Key, risking unauthorized access to administrative functions and sensitive AI model configurations.",
			cwe:         "CWE-798", keywords: []string{"sk-ant-admin01"},
			remediation: "Imported from Gitleaks: anthropic-admin-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-167", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bcmVmd[A-Za-z0-9]{59}\b`,
			description: "Detected an Artifactory reference token, posing a risk of impersonation and unauthorized access to the central repository.",
			cwe:         "CWE-798", keywords: []string{"cmvmd"},
			remediation: "Imported from Gitleaks: artifactory-reference-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-168", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b((?:sc|ext|scauth|authress)_(?i)[a-z0-9]{5,30}\.[a-z0-9]{4,6}\.(?-i:acc)[_-][a-z0-9-]{10,32}\.[a-z0-9+/_=-]{30,120})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a possible Authress Service Client Access Key, which may compromise access control services and sensitive data.",
			cwe:         "CWE-798", keywords: []string{"sc_", "ext_", "scauth_", "authress_"},
			remediation: "Imported from Gitleaks: authress-service-client-access-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-169", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(ABSK[A-Za-z0-9+/]{109,269}={0,2})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a pattern that may indicate long-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
			cwe:         "CWE-798", keywords: []string{"absk"},
			remediation: "Imported from Gitleaks: aws-amazon-bedrock-api-key-long-lived",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-170", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `bedrock-api-key-YmVkcm9jay5hbWF6b25hd3MuY29t`,
			description: "Identified a pattern that may indicate short-lived Amazon Bedrock API keys, risking unauthorized Amazon Bedrock usage",
			cwe:         "CWE-798", keywords: []string{"bedrock-api-key-"},
			remediation: "Imported from Gitleaks: aws-amazon-bedrock-api-key-short-lived",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-171", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:beamer)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(b_[a-z0-9=_\-]{44})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Beamer API token, potentially compromising content management and exposing sensitive notifications and updates.",
			cwe:         "CWE-798", keywords: []string{"beamer"},
			remediation: "Imported from Gitleaks: beamer-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-172", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:bitbucket)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a potential Bitbucket Client Secret, posing a risk of compromised code repositories and unauthorized access.",
			cwe:         "CWE-798", keywords: []string{"bitbucket"},
			remediation: "Imported from Gitleaks: bitbucket-client-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-173", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Bittrex Access Key, which could lead to unauthorized access to cryptocurrency trading accounts and financial loss.",
			cwe:         "CWE-798", keywords: []string{"bittrex"},
			remediation: "Imported from Gitleaks: bittrex-access-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-174", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:bittrex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Bittrex Secret Key, potentially compromising cryptocurrency transactions and financial security.",
			cwe:         "CWE-798", keywords: []string{"bittrex"},
			remediation: "Imported from Gitleaks: bittrex-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-175", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Mm]eraki|MERAKI))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Cisco Meraki is a cloud-managed IT solution that provides networking, security, and device management through an easy-to-use interface.",
			cwe:         "CWE-798", keywords: []string{"meraki"},
			remediation: "Imported from Gitleaks: cisco-meraki-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-176", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(4b1d[A-Za-z0-9]{38})\b`,
			description: "Identified a pattern that may indicate clickhouse cloud API secret key, risking unauthorized clickhouse cloud api access and data breaches on ClickHouse Cloud platforms.",
			cwe:         "CWE-798", keywords: []string{"4b1d"},
			remediation: "Imported from Gitleaks: clickhouse-cloud-api-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-177", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)CLOJARS_[a-z0-9]{60}`,
			description: "Uncovered a possible Clojars API token, risking unauthorized access to Clojure libraries and potential code manipulation.",
			cwe:         "CWE-798", keywords: []string{"clojars_"},
			remediation: "Imported from Gitleaks: clojars-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-178", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:cloudflare)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{37})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Cloudflare Global API Key, potentially compromising cloud application deployments and operational security.",
			cwe:         "CWE-798", keywords: []string{"cloudflare"},
			remediation: "Imported from Gitleaks: cloudflare-global-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-179", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(v1\.0-[a-f0-9]{24}-[a-f0-9]{146})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Cloudflare Origin CA Key, potentially compromising cloud application deployments and operational security.",
			cwe:         "CWE-798", keywords: []string{"cloudflare", "v1.0-"},
			remediation: "Imported from Gitleaks: cloudflare-origin-ca-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-180", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:coinbase)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Coinbase Access Token, posing a risk of unauthorized access to cryptocurrency accounts and financial transactions.",
			cwe:         "CWE-798", keywords: []string{"coinbase"},
			remediation: "Imported from Gitleaks: coinbase-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-181", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:confluent)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Confluent Secret Key, potentially risking unauthorized operations and data access within Confluent services.",
			cwe:         "CWE-798", keywords: []string{"confluent"},
			remediation: "Imported from Gitleaks: confluent-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-182", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:contentful)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{43})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Contentful delivery API token, posing a risk to content management systems and data integrity.",
			cwe:         "CWE-798", keywords: []string{"contentful"},
			remediation: "Imported from Gitleaks: contentful-delivery-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-183", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bcurl\b(?:.*?|.*?(?:[\r\n]{1,2}.*?){1,5})[ \t\n\r](?:-H|--header)(?:=|[ \t]{0,5})(?:"(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))"|'(?i)(?:Authorization:[ \t]{0,5}(?:Basic[ \t]([a-z0-9+/]{8,}={0,3})|(?:Bearer|(?:Api-)?Token)[ \t]([\w=~@.+/-]{8,})|([\w=~@.+/-]{8,}))|(?:(?:X-(?:[a-z]+-)?)?(?:Api-?)?(?:Key|Token)):[ \t]{0,5}([\w=~@.+/-]{8,}))')(?:\B|\s|\z)`,
			description: "Discovered a potential authorization token provided in a curl command header, which could compromise the curl accessed resource.",
			cwe:         "CWE-798", keywords: []string{"curl"},
			remediation: "Imported from Gitleaks: curl-auth-header",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-184", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bcurl\b(?:.*|.*(?:[\r\n]{1,2}.*){1,5})[ \t\n\r](?:-u|--user)(?:=|[ \t]{0,5})("(:[^"]{3,}|[^:"]{3,}:|[^:"]{3,}:[^"]{3,})"|'([^:']{3,}:[^']{3,})'|((?:"[^"]{3,}"|'[^']{3,}'|[\w$@.-]+):(?:"[^"]{3,}"|'[^']{3,}'|[\w${}@.-]+)))(?:\s|\z)`,
			description: "Discovered a potential basic authorization token provided in a curl command, which could compromise the curl accessed resource.",
			cwe:         "CWE-798", keywords: []string{"curl"},
			remediation: "Imported from Gitleaks: curl-auth-user",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-185", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:dnkey)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(dnkey-[a-z0-9=_\-]{26}-[a-z0-9=_\-]{52})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Defined Networking API token, which could lead to unauthorized network operations and data breaches.",
			cwe:         "CWE-798", keywords: []string{"dnkey"},
			remediation: "Imported from Gitleaks: defined-networking-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-186", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(dop_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a DigitalOcean Personal Access Token, posing a threat to cloud infrastructure security and data privacy.",
			cwe:         "CWE-798", keywords: []string{"dop_v1_"},
			remediation: "Imported from Gitleaks: digitalocean-pat",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-187", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(dor_v1_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a DigitalOcean OAuth Refresh Token, which could allow prolonged unauthorized access and resource manipulation.",
			cwe:         "CWE-798", keywords: []string{"dor_v1_"},
			remediation: "Imported from Gitleaks: digitalocean-refresh-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-188", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:discord)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a potential Discord client secret, risking compromised Discord bot integrations and data leaks.",
			cwe:         "CWE-798", keywords: []string{"discord"},
			remediation: "Imported from Gitleaks: discord-client-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-189", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `dp\.pt\.(?i)[a-z0-9]{43}`,
			description: "Discovered a Doppler API token, posing a risk to environment and secrets management security.",
			cwe:         "CWE-798", keywords: []string{"dp.pt."},
			remediation: "Imported from Gitleaks: doppler-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-190", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:droneci)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Droneci Access Token, potentially compromising continuous integration and deployment workflows.",
			cwe:         "CWE-798", keywords: []string{"droneci"},
			remediation: "Imported from Gitleaks: droneci-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-191", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{11}(AAAAAAAAAA)[a-z0-9\-_=]{43})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Dropbox long-lived API token, risking prolonged unauthorized access to cloud storage and sensitive data.",
			cwe:         "CWE-798", keywords: []string{"dropbox"},
			remediation: "Imported from Gitleaks: dropbox-long-lived-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-192", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:dropbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(sl\.[a-z0-9\-=_]{135})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Dropbox short-lived API token, posing a risk of temporary but potentially harmful data access and manipulation.",
			cwe:         "CWE-798", keywords: []string{"dropbox"},
			remediation: "Imported from Gitleaks: dropbox-short-lived-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-193", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `duffel_(?:test|live)_(?i)[a-z0-9_\-=]{43}`,
			description: "Uncovered a Duffel API token, which may compromise travel platform integrations and sensitive customer data.",
			cwe:         "CWE-798", keywords: []string{"duffel_"},
			remediation: "Imported from Gitleaks: duffel-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-194", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `dt0c01\.(?i)[a-z0-9]{24}\.[a-z0-9]{64}`,
			description: "Detected a Dynatrace API token, potentially risking application performance monitoring and data exposure.",
			cwe:         "CWE-798", keywords: []string{"dt0c01."},
			remediation: "Imported from Gitleaks: dynatrace-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-195", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bEZAK(?i)[a-z0-9]{54}\b`,
			description: "Identified an EasyPost API token, which could lead to unauthorized postal and shipment service access and data exposure.",
			cwe:         "CWE-798", keywords: []string{"ezak"},
			remediation: "Imported from Gitleaks: easypost-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-196", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bEZTK(?i)[a-z0-9]{54}\b`,
			description: "Detected an EasyPost test API token, risking exposure of test environments and potentially sensitive shipment data.",
			cwe:         "CWE-798", keywords: []string{"eztk"},
			remediation: "Imported from Gitleaks: easypost-test-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-197", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:(?-i:ETSY|[Ee]tsy))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found an Etsy Access Token, potentially compromising Etsy shop management and customer data.",
			cwe:         "CWE-798", keywords: []string{"etsy"},
			remediation: "Imported from Gitleaks: etsy-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-198", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(\d{15,16}(\||%)[0-9a-z\-_]{27,40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Facebook Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
			cwe:         "CWE-798", keywords: []string{"facebook"},
			remediation: "Imported from Gitleaks: facebook-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-199", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(EAA[MC](?i)[a-z0-9]{100,})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Facebook Page Access Token, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
			cwe:         "CWE-798", keywords: []string{"eaam", "eaac"},
			remediation: "Imported from Gitleaks: facebook-page-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-200", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:facebook)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Facebook Application secret, posing a risk of unauthorized access to Facebook accounts and personal data exposure.",
			cwe:         "CWE-798", keywords: []string{"facebook"},
			remediation: "Imported from Gitleaks: facebook-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-201", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:fastly)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Fastly API key, which may compromise CDN and edge cloud services, leading to content delivery and security issues.",
			cwe:         "CWE-798", keywords: []string{"fastly"},
			remediation: "Imported from Gitleaks: fastly-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-202", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Finicity API token, potentially risking financial data access and unauthorized financial operations.",
			cwe:         "CWE-798", keywords: []string{"finicity"},
			remediation: "Imported from Gitleaks: finicity-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-203", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:finicity)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Finicity Client Secret, which could lead to compromised financial service integrations and data breaches.",
			cwe:         "CWE-798", keywords: []string{"finicity"},
			remediation: "Imported from Gitleaks: finicity-client-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-204", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:finnhub)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Finnhub Access Token, risking unauthorized access to financial market data and analytics.",
			cwe:         "CWE-798", keywords: []string{"finnhub"},
			remediation: "Imported from Gitleaks: finnhub-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-205", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:flickr)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Flickr Access Token, posing a risk of unauthorized photo management and potential data leakage.",
			cwe:         "CWE-798", keywords: []string{"flickr"},
			remediation: "Imported from Gitleaks: flickr-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-206", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `FLWSECK_TEST-(?i)[a-h0-9]{12}`,
			description: "Uncovered a Flutterwave Encryption Key, which may compromise payment processing and sensitive financial information.",
			cwe:         "CWE-798", keywords: []string{"flwseck_test"},
			remediation: "Imported from Gitleaks: flutterwave-encryption-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-207", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `FLWPUBK_TEST-(?i)[a-h0-9]{32}-X`,
			description: "Detected a Finicity Public Key, potentially exposing public cryptographic operations and integrations.",
			cwe:         "CWE-798", keywords: []string{"flwpubk_test"},
			remediation: "Imported from Gitleaks: flutterwave-public-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-208", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `FLWSECK_TEST-(?i)[a-h0-9]{32}-X`,
			description: "Identified a Flutterwave Secret Key, risking unauthorized financial transactions and data breaches.",
			cwe:         "CWE-798", keywords: []string{"flwseck_test"},
			remediation: "Imported from Gitleaks: flutterwave-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-209", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b((?:fo1_[\w-]{43}|fm1[ar]_[a-zA-Z0-9+\/]{100,}={0,3}|fm2_[a-zA-Z0-9+\/]{100,}={0,3}))(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Fly.io API key",
			cwe:         "CWE-798", keywords: []string{"fo1_", "fm1", "fm2_"},
			remediation: "Imported from Gitleaks: flyio-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-210", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `fio-u-(?i)[a-z0-9\-_=]{64}`,
			description: "Found a Frame.io API token, potentially compromising video collaboration and project management.",
			cwe:         "CWE-798", keywords: []string{"fio-u-"},
			remediation: "Imported from Gitleaks: frameio-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-211", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)["']secret_key["']\s*=>\s*["'](sk_[\S]{29})["']`,
			description: "Detected a Freemius secret key, potentially exposing sensitive information.",
			cwe:         "CWE-798", keywords: []string{"secret_key"},
			remediation: "Imported from Gitleaks: freemius-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-212", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:freshbooks)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Freshbooks Access Token, posing a risk to accounting software access and sensitive financial data exposure.",
			cwe:         "CWE-798", keywords: []string{"freshbooks"},
			remediation: "Imported from Gitleaks: freshbooks-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-213", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?:ghu|ghs)_[0-9a-zA-Z]{36}`,
			description: "Identified a GitHub App Token, which may compromise GitHub application integrations and source code security.",
			cwe:         "CWE-798", keywords: []string{"ghu_", "ghs_"},
			remediation: "Imported from Gitleaks: github-app-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-214", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `github_pat_\w{82}`,
			description: "Found a GitHub Fine-Grained Personal Access Token, risking unauthorized repository access and code manipulation.",
			cwe:         "CWE-798", keywords: []string{"github_pat_"},
			remediation: "Imported from Gitleaks: github-fine-grained-pat",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-215", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `gho_[0-9a-zA-Z]{36}`,
			description: "Discovered a GitHub OAuth Access Token, posing a risk of compromised GitHub account integrations and data leaks.",
			cwe:         "CWE-798", keywords: []string{"gho_"},
			remediation: "Imported from Gitleaks: github-oauth",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-216", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `ghp_[0-9a-zA-Z]{36}`,
			description: "Uncovered a GitHub Personal Access Token, potentially leading to unauthorized repository access and sensitive content exposure.",
			cwe:         "CWE-798", keywords: []string{"ghp_"},
			remediation: "Imported from Gitleaks: github-pat",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-217", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `ghr_[0-9a-zA-Z]{36}`,
			description: "Detected a GitHub Refresh Token, which could allow prolonged unauthorized access to GitHub services.",
			cwe:         "CWE-798", keywords: []string{"ghr_"},
			remediation: "Imported from Gitleaks: github-refresh-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-218", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glcbt-[0-9a-zA-Z]{1,5}_[0-9a-zA-Z_-]{20}`,
			description: "Identified a GitLab CI/CD Job Token, potential access to projects and some APIs on behalf of a user while the CI job is running.",
			cwe:         "CWE-798", keywords: []string{"glcbt-"},
			remediation: "Imported from Gitleaks: gitlab-cicd-job-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-219", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `gldt-[0-9a-zA-Z_\-]{20}`,
			description: "Identified a GitLab Deploy Token, risking access to repositories, packages and containers with write access.",
			cwe:         "CWE-798", keywords: []string{"gldt-"},
			remediation: "Imported from Gitleaks: gitlab-deploy-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-220", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glffct-[0-9a-zA-Z_\-]{20}`,
			description: "Identified a GitLab feature flag client token, risks exposing user lists and features flags used by an application.",
			cwe:         "CWE-798", keywords: []string{"glffct-"},
			remediation: "Imported from Gitleaks: gitlab-feature-flag-client-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-221", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glft-[0-9a-zA-Z_\-]{20}`,
			description: "Identified a GitLab feed token, risking exposure of user data.",
			cwe:         "CWE-798", keywords: []string{"glft-"},
			remediation: "Imported from Gitleaks: gitlab-feed-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-222", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glimt-[0-9a-zA-Z_\-]{25}`,
			description: "Identified a GitLab incoming mail token, risking manipulation of data sent by mail.",
			cwe:         "CWE-798", keywords: []string{"glimt-"},
			remediation: "Imported from Gitleaks: gitlab-incoming-mail-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-223", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glagent-[0-9a-zA-Z_\-]{50}`,
			description: "Identified a GitLab Kubernetes Agent token, risking access to repos and registry of projects connected via agent.",
			cwe:         "CWE-798", keywords: []string{"glagent-"},
			remediation: "Imported from Gitleaks: gitlab-kubernetes-agent-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-224", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `gloas-[0-9a-zA-Z_\-]{64}`,
			description: "Identified a GitLab OIDC Application Secret, risking access to apps using GitLab as authentication provider.",
			cwe:         "CWE-798", keywords: []string{"gloas-"},
			remediation: "Imported from Gitleaks: gitlab-oauth-app-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-225", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glpat-[\w-]{20}`,
			description: "Identified a GitLab Personal Access Token, risking unauthorized access to GitLab repositories and codebase exposure.",
			cwe:         "CWE-798", keywords: []string{"glpat-"},
			remediation: "Imported from Gitleaks: gitlab-pat",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-226", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bglpat-[0-9a-zA-Z_-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`,
			description: "Identified a GitLab Personal Access Token (routable), risking unauthorized access to GitLab repositories and codebase exposure.",
			cwe:         "CWE-798", keywords: []string{"glpat-"},
			remediation: "Imported from Gitleaks: gitlab-pat-routable",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-227", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glptt-[0-9a-f]{40}`,
			description: "Found a GitLab Pipeline Trigger Token, potentially compromising continuous integration workflows and project security.",
			cwe:         "CWE-798", keywords: []string{"glptt-"},
			remediation: "Imported from Gitleaks: gitlab-ptt",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-228", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `GR1348941[\w-]{20}`,
			description: "Discovered a GitLab Runner Registration Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
			cwe:         "CWE-798", keywords: []string{"gr1348941"},
			remediation: "Imported from Gitleaks: gitlab-rrt",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-229", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glrt-[0-9a-zA-Z_\-]{20}`,
			description: "Discovered a GitLab Runner Authentication Token, posing a risk to CI/CD pipeline integrity and unauthorized access.",
			cwe:         "CWE-798", keywords: []string{"glrt-"},
			remediation: "Imported from Gitleaks: gitlab-runner-authentication-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-230", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bglrt-t\d_[0-9a-zA-Z_\-]{27,300}\.[0-9a-z]{2}[0-9a-z]{7}\b`,
			description: "Discovered a GitLab Runner Authentication Token (Routable), posing a risk to CI/CD pipeline integrity and unauthorized access.",
			cwe:         "CWE-798", keywords: []string{"glrt-"},
			remediation: "Imported from Gitleaks: gitlab-runner-authentication-token-routable",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-231", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `glsoat-[0-9a-zA-Z_\-]{20}`,
			description: "Discovered a GitLab SCIM Token, posing a risk to unauthorized access for a organization or instance.",
			cwe:         "CWE-798", keywords: []string{"glsoat-"},
			remediation: "Imported from Gitleaks: gitlab-scim-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-232", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `_gitlab_session=[0-9a-z]{32}`,
			description: "Discovered a GitLab Session Cookie, posing a risk to unauthorized access to a user account.",
			cwe:         "CWE-798", keywords: []string{"_gitlab_session="},
			remediation: "Imported from Gitleaks: gitlab-session-cookie",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-233", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:gitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Gitter Access Token, which may lead to unauthorized access to chat and communication services.",
			cwe:         "CWE-798", keywords: []string{"gitter"},
			remediation: "Imported from Gitleaks: gitter-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-234", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:gocardless)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(live_(?i)[a-z0-9\-_=]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a GoCardless API token, potentially risking unauthorized direct debit payment operations and financial data exposure.",
			cwe:         "CWE-798", keywords: []string{"live_", "gocardless"},
			remediation: "Imported from Gitleaks: gocardless-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-235", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(eyJrIjoi[A-Za-z0-9]{70,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Grafana API key, which could compromise monitoring dashboards and sensitive data analytics.",
			cwe:         "CWE-798", keywords: []string{"eyjrijoi"},
			remediation: "Imported from Gitleaks: grafana-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-236", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(glc_[A-Za-z0-9+/]{32,400}={0,3})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Grafana cloud API token, risking unauthorized access to cloud-based monitoring services and data exposure.",
			cwe:         "CWE-798", keywords: []string{"glc_"},
			remediation: "Imported from Gitleaks: grafana-cloud-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-237", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(glsa_[A-Za-z0-9]{32}_[A-Fa-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Grafana service account token, posing a risk of compromised monitoring services and data integrity.",
			cwe:         "CWE-798", keywords: []string{"glsa_"},
			remediation: "Imported from Gitleaks: grafana-service-account-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-238", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?:pat|sat)\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9]{24}\.[a-zA-Z0-9]{20}`,
			description: "Identified a Harness Access Token (PAT or SAT), risking unauthorized access to a Harness account.",
			cwe:         "CWE-798", keywords: []string{"pat.", "sat."},
			remediation: "Imported from Gitleaks: harness-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-239", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[a-z0-9]{14}\.(?-i:atlasv1)\.[a-z0-9\-_=]{60,70}`,
			description: "Uncovered a HashiCorp Terraform user/org API token, which may lead to unauthorized infrastructure management and security breaches.",
			cwe:         "CWE-798", keywords: []string{"atlasv1"},
			remediation: "Imported from Gitleaks: hashicorp-tf-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-240", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:administrator_login_password|password)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}("[a-z0-9=_\-]{8,20}")(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a HashiCorp Terraform password field, risking unauthorized infrastructure configuration and security breaches.",
			cwe:         "CWE-798", keywords: []string{"administrator_login_password", "password"},
			remediation: "Imported from Gitleaks: hashicorp-tf-password",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-241", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:heroku)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
			cwe:         "CWE-798", keywords: []string{"heroku"},
			remediation: "Imported from Gitleaks: heroku-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-242", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b((HRKU-AA[0-9a-zA-Z_-]{58}))(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Heroku API Key, potentially compromising cloud application deployments and operational security.",
			cwe:         "CWE-798", keywords: []string{"hrku-aa"},
			remediation: "Imported from Gitleaks: heroku-api-key-v2",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-243", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:hubspot)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9A-F]{8}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{4}-[0-9A-F]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a HubSpot API Token, posing a risk to CRM data integrity and unauthorized marketing operations.",
			cwe:         "CWE-798", keywords: []string{"hubspot"},
			remediation: "Imported from Gitleaks: hubspot-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-244", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(hf_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Hugging Face Access token, which could lead to unauthorized access to AI models and sensitive data.",
			cwe:         "CWE-798", keywords: []string{"hf_"},
			remediation: "Imported from Gitleaks: huggingface-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-245", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(api_org_(?i:[a-z]{34}))(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Hugging Face Organization API token, potentially compromising AI organization accounts and associated data.",
			cwe:         "CWE-798", keywords: []string{"api_org_"},
			remediation: "Imported from Gitleaks: huggingface-organization-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-246", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(ico-[a-zA-Z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected an Infracost API Token, risking unauthorized access to cloud cost estimation tools and financial data.",
			cwe:         "CWE-798", keywords: []string{"ico-"},
			remediation: "Imported from Gitleaks: infracost-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-247", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:intercom)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{60})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified an Intercom API Token, which could compromise customer communication channels and data privacy.",
			cwe:         "CWE-798", keywords: []string{"intercom"},
			remediation: "Imported from Gitleaks: intercom-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-248", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(s-s4t2(?:ud|af)-(?i)[abcdef0123456789]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Intra42 client secret, which could lead to unauthorized access to the 42School API and sensitive data.",
			cwe:         "CWE-798", keywords: []string{"intra", "s-s4t2ud-", "s-s4t2af-"},
			remediation: "Imported from Gitleaks: intra42-client-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-249", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{73})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a JFrog API Key, posing a risk of unauthorized access to software artifact repositories and build pipelines.",
			cwe:         "CWE-798", keywords: []string{"jfrog", "artifactory", "bintray", "xray"},
			remediation: "Imported from Gitleaks: jfrog-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-250", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:jfrog|artifactory|bintray|xray)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a JFrog Identity Token, potentially compromising access to JFrog services and sensitive software artifacts.",
			cwe:         "CWE-798", keywords: []string{"jfrog", "artifactory", "bintray", "xray"},
			remediation: "Imported from Gitleaks: jfrog-identity-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-251", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(ey[a-zA-Z0-9]{17,}\.ey[a-zA-Z0-9\/\\_-]{17,}\.(?:[a-zA-Z0-9\/\\_-]{10,}={0,2})?)(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a JSON Web Token, which may lead to unauthorized access to web applications and sensitive user data.",
			cwe:         "CWE-798", keywords: []string{"ey"},
			remediation: "Imported from Gitleaks: jwt",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-252", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bZXlK(?:(?P<alg>aGJHY2lPaU)|(?P<apu>aGNIVWlPaU)|(?P<apv>aGNIWWlPaU)|(?P<aud>aGRXUWlPaU)|(?P<b64>aU5qUWlP)|(?P<crit>amNtbDBJanBi)|(?P<cty>amRIa2lPaU)|(?P<epk>bGNHc2lPbn)|(?P<enc>bGJtTWlPaU)|(?P<jku>cWEzVWlPaU)|(?P<jwk>cWQyc2lPb)|(?P<iss>cGMzTWlPaU)|(?P<iv>cGRpSTZJ)|(?P<kid>cmFXUWlP)|(?P<key_ops>clpYbGZiM0J6SWpwY)|(?P<kty>cmRIa2lPaUp)|(?P<nonce>dWIyNWpaU0k2)|(?P<p2c>d01tTWlP)|(?P<p2s>d01uTWlPaU)|(?P<ppt>d2NIUWlPaU)|(?P<sub>emRXSWlPaU)|(?P<svt>emRuUWlP)|(?P<tag>MFlXY2lPaU)|(?P<typ>MGVYQWlPaUp)|(?P<url>MWNtd2l)|(?P<use>MWMyVWlPaUp)|(?P<ver>MlpYSWlPaU)|(?P<version>MlpYSnphVzl1SWpv)|(?P<x>NElqb2)|(?P<x5c>NE5XTWlP)|(?P<x5t>NE5YUWlPaU)|(?P<x5ts256>NE5YUWpVekkxTmlJNkl)|(?P<x5u>NE5YVWlPaU)|(?P<zip>NmFYQWlPaU))[a-zA-Z0-9\/\\_+\-\r\n]{40,}={0,2}`,
			description: "Detected a Base64-encoded JSON Web Token, posing a risk of exposing encoded authentication and data exchange information.",
			cwe:         "CWE-798", keywords: []string{"zxlk"},
			remediation: "Imported from Gitleaks: jwt-base64",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-253", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:kraken)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9\/=_\+\-]{80,90})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Kraken Access Token, potentially compromising cryptocurrency trading accounts and financial security.",
			cwe:         "CWE-798", keywords: []string{"kraken"},
			remediation: "Imported from Gitleaks: kraken-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-254", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)(?:\bkind:[ \t]*["']?\bsecret\b["']?(?s:.){0,200}?\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))|\bdata:(?s:.){0,100}?\s+([\w.-]+:(?:[ \t]*(?:\||>[-+]?)\s+)?[ \t]*(?:["']?[a-z0-9+/]{10,}={0,3}["']?|\{\{[ \t\w"|$:=,.-]+}}|""|''))(?s:.){0,200}?\bkind:[ \t]*["']?\bsecret\b["']?)`,
			description: "Possible Kubernetes Secret detected, posing a risk of leaking credentials/tokens from your deployments",
			cwe:         "CWE-798", keywords: []string{"secret"},
			remediation: "Imported from Gitleaks: kubernetes-secret-yaml",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-255", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Kucoin Access Token, risking unauthorized access to cryptocurrency exchange services and transactions.",
			cwe:         "CWE-798", keywords: []string{"kucoin"},
			remediation: "Imported from Gitleaks: kucoin-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-256", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:kucoin)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Kucoin Secret Key, which could lead to compromised cryptocurrency operations and financial data breaches.",
			cwe:         "CWE-798", keywords: []string{"kucoin"},
			remediation: "Imported from Gitleaks: kucoin-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-257", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:launchdarkly)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Launchdarkly Access Token, potentially compromising feature flag management and application functionality.",
			cwe:         "CWE-798", keywords: []string{"launchdarkly"},
			remediation: "Imported from Gitleaks: launchdarkly-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-258", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `lin_api_(?i)[a-z0-9]{40}`,
			description: "Detected a Linear API Token, posing a risk to project management tools and sensitive task data.",
			cwe:         "CWE-798", keywords: []string{"lin_api_"},
			remediation: "Imported from Gitleaks: linear-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-259", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:linear)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Linear Client Secret, which may compromise secure integrations and sensitive project management data.",
			cwe:         "CWE-798", keywords: []string{"linear"},
			remediation: "Imported from Gitleaks: linear-client-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-260", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{14})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a LinkedIn Client ID, risking unauthorized access to LinkedIn integrations and professional data exposure.",
			cwe:         "CWE-798", keywords: []string{"linkedin", "linked_in", "linked-in"},
			remediation: "Imported from Gitleaks: linkedin-client-id",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-261", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:linked[_-]?in)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a LinkedIn Client secret, potentially compromising LinkedIn application integrations and user data.",
			cwe:         "CWE-798", keywords: []string{"linkedin", "linked_in", "linked-in"},
			remediation: "Imported from Gitleaks: linkedin-client-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-262", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((live|test)_[a-f0-9]{35})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Lob API Key, which could lead to unauthorized access to mailing and address verification services.",
			cwe:         "CWE-798", keywords: []string{"test_", "live_"},
			remediation: "Imported from Gitleaks: lob-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-263", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:lob)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((test|live)_pub_[a-f0-9]{31})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Lob Publishable API Key, posing a risk of exposing mail and print service integrations.",
			cwe:         "CWE-798", keywords: []string{"test_pub", "live_pub", "_pub"},
			remediation: "Imported from Gitleaks: lob-pub-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-264", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:looker)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Looker Client ID, risking unauthorized access to a Looker account and exposing sensitive data.",
			cwe:         "CWE-798", keywords: []string{"looker"},
			remediation: "Imported from Gitleaks: looker-client-id",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-265", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:looker)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Looker Client Secret, risking unauthorized access to a Looker account and exposing sensitive data.",
			cwe:         "CWE-798", keywords: []string{"looker"},
			remediation: "Imported from Gitleaks: looker-client-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-266", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:MailchimpSDK.initialize|mailchimp)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{32}-us\d\d)(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Mailchimp API key, potentially compromising email marketing campaigns and subscriber data.",
			cwe:         "CWE-798", keywords: []string{"mailchimp"},
			remediation: "Imported from Gitleaks: mailchimp-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-267", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(key-[a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Mailgun private API token, risking unauthorized email service operations and data breaches.",
			cwe:         "CWE-798", keywords: []string{"mailgun"},
			remediation: "Imported from Gitleaks: mailgun-private-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-268", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pubkey-[a-f0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Mailgun public validation key, which could expose email verification processes and associated data.",
			cwe:         "CWE-798", keywords: []string{"mailgun"},
			remediation: "Imported from Gitleaks: mailgun-pub-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-269", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:mailgun)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-h0-9]{32}-[a-h0-9]{8}-[a-h0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Mailgun webhook signing key, potentially compromising email automation and data integrity.",
			cwe:         "CWE-798", keywords: []string{"mailgun"},
			remediation: "Imported from Gitleaks: mailgun-signing-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-270", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:mapbox)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(pk\.[a-z0-9]{60}\.[a-z0-9]{22})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a MapBox API token, posing a risk to geospatial services and sensitive location data exposure.",
			cwe:         "CWE-798", keywords: []string{"mapbox"},
			remediation: "Imported from Gitleaks: mapbox-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-271", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:mattermost)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{26})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Mattermost Access Token, which may compromise team communication channels and data privacy.",
			cwe:         "CWE-798", keywords: []string{"mattermost"},
			remediation: "Imported from Gitleaks: mattermost-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-272", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b([A-Za-z0-9]{6}_[A-Za-z0-9]{29}_mmk)(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a potential MaxMind license key.",
			cwe:         "CWE-798", keywords: []string{"_mmk"},
			remediation: "Imported from Gitleaks: maxmind-license-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-273", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{25})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a MessageBird API token, risking unauthorized access to communication platforms and message data.",
			cwe:         "CWE-798", keywords: []string{"messagebird", "message-bird", "message_bird"},
			remediation: "Imported from Gitleaks: messagebird-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-274", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:message[_-]?bird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a MessageBird client ID, potentially compromising API integrations and sensitive communication data.",
			cwe:         "CWE-798", keywords: []string{"messagebird", "message-bird", "message_bird"},
			remediation: "Imported from Gitleaks: messagebird-client-id",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-275", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `https://[a-z0-9]+\.webhook\.office\.com/webhookb2/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}@[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}/IncomingWebhook/[a-z0-9]{32}/[a-z0-9]{8}-([a-z0-9]{4}-){3}[a-z0-9]{12}`,
			description: "Uncovered a Microsoft Teams Webhook, which could lead to unauthorized access to team collaboration tools and data leaks.",
			cwe:         "CWE-798", keywords: []string{"webhook.office.com", "webhookb2", "incomingwebhook"},
			remediation: "Imported from Gitleaks: microsoft-teams-webhook",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-276", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:netlify)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{40,46})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Netlify Access Token, potentially compromising web hosting services and site management.",
			cwe:         "CWE-798", keywords: []string{"netlify"},
			remediation: "Imported from Gitleaks: netlify-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-277", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(NRJS-[a-f0-9]{19})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a New Relic ingest browser API token, risking unauthorized access to application performance data and analytics.",
			cwe:         "CWE-798", keywords: []string{"nrjs-"},
			remediation: "Imported from Gitleaks: new-relic-browser-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-278", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(NRII-[a-z0-9-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a New Relic insight insert key, compromising data injection into the platform.",
			cwe:         "CWE-798", keywords: []string{"nrii-"},
			remediation: "Imported from Gitleaks: new-relic-insert-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-279", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a New Relic user API ID, posing a risk to application monitoring services and data integrity.",
			cwe:         "CWE-798", keywords: []string{"new-relic", "newrelic", "new_relic"},
			remediation: "Imported from Gitleaks: new-relic-user-api-id",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-280", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:new-relic|newrelic|new_relic)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(NRAK-[a-z0-9]{27})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a New Relic user API Key, which could lead to compromised application insights and performance monitoring.",
			cwe:         "CWE-798", keywords: []string{"nrak"},
			remediation: "Imported from Gitleaks: new-relic-user-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-281", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(ntn_[0-9]{11}[A-Za-z0-9]{32}[A-Za-z0-9]{3})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Notion API token",
			cwe:         "CWE-798", keywords: []string{"ntn_"},
			remediation: "Imported from Gitleaks: notion-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-282", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(npm_[a-z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered an npm access token, potentially compromising package management and code repository access.",
			cwe:         "CWE-798", keywords: []string{"npm_"},
			remediation: "Imported from Gitleaks: npm-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-283", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)<add key=\"(?:(?:ClearText)?Password)\"\s*value=\"(.{8,})\"\s*/>`,
			description: "Identified a password within a Nuget config file, potentially compromising package management access.",
			cwe:         "CWE-798", keywords: []string{"<add key="},
			remediation: "Imported from Gitleaks: nuget-config-password",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-284", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:nytimes|new-york-times,|newyorktimes)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9=_\-]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Nytimes Access Token, risking unauthorized access to New York Times APIs and content services.",
			cwe:         "CWE-798", keywords: []string{"nytimes", "new-york-times", "newyorktimes"},
			remediation: "Imported from Gitleaks: nytimes-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-285", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(API-[A-Z0-9]{26})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a potential Octopus Deploy API key, risking application deployments and operational security.",
			cwe:         "CWE-798", keywords: []string{"api-"},
			remediation: "Imported from Gitleaks: octopus-deploy-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-286", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Oo]kta|OKTA))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(00[\w=\-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified an Okta Access Token, which may compromise identity management services and user authentication data.",
			cwe:         "CWE-798", keywords: []string{"okta"},
			remediation: "Imported from Gitleaks: okta-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-287", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(sk-(?:proj|svcacct|admin)-(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})T3BlbkFJ(?:[A-Za-z0-9_-]{74}|[A-Za-z0-9_-]{58})\b|sk-[a-zA-Z0-9]{20}T3BlbkFJ[a-zA-Z0-9]{20})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found an OpenAI API Key, posing a risk of unauthorized access to AI services and data manipulation.",
			cwe:         "CWE-798", keywords: []string{"t3blbkfj"},
			remediation: "Imported from Gitleaks: openai-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-288", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(sha256~[\w-]{43})(?:[^\w-]|\z)`,
			description: "Found an OpenShift user token, potentially compromising an OpenShift/Kubernetes cluster.",
			cwe:         "CWE-798", keywords: []string{"sha256~"},
			remediation: "Imported from Gitleaks: openshift-user-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-289", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(pplx-[a-zA-Z0-9]{48})(?:[\x60'"\s;]|\\[nr]|$|\b)`,
			description: "Detected a Perplexity API key, which could lead to unauthorized access to Perplexity AI services and data exposure.",
			cwe:         "CWE-798", keywords: []string{"pplx-"},
			remediation: "Imported from Gitleaks: perplexity-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-291", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(access-(?:sandbox|development|production)-[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Plaid API Token, potentially compromising financial data aggregation and banking services.",
			cwe:         "CWE-798", keywords: []string{"plaid"},
			remediation: "Imported from Gitleaks: plaid-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-292", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{24})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Plaid Client ID, which could lead to unauthorized financial service integrations and data breaches.",
			cwe:         "CWE-798", keywords: []string{"plaid"},
			remediation: "Imported from Gitleaks: plaid-client-id",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-293", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:plaid)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Plaid Secret key, risking unauthorized access to financial accounts and sensitive transaction data.",
			cwe:         "CWE-798", keywords: []string{"plaid"},
			remediation: "Imported from Gitleaks: plaid-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-294", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(pscale_tkn_(?i)[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a PlanetScale API token, potentially compromising database management and operations.",
			cwe:         "CWE-798", keywords: []string{"pscale_tkn_"},
			remediation: "Imported from Gitleaks: planetscale-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-295", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(pscale_oauth_[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a PlanetScale OAuth token, posing a risk to database access control and sensitive data integrity.",
			cwe:         "CWE-798", keywords: []string{"pscale_oauth_"},
			remediation: "Imported from Gitleaks: planetscale-oauth-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-296", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(pscale_pw_(?i)[\w=\.-]{32,64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a PlanetScale password, which could lead to unauthorized database operations and data breaches.",
			cwe:         "CWE-798", keywords: []string{"pscale_pw_"},
			remediation: "Imported from Gitleaks: planetscale-password",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-297", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(PMAK-(?i)[a-f0-9]{24}\-[a-f0-9]{34})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Postman API token, potentially compromising API testing and development workflows.",
			cwe:         "CWE-798", keywords: []string{"pmak-"},
			remediation: "Imported from Gitleaks: postman-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-298", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(pnu_[a-zA-Z0-9]{36})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Prefect API token, risking unauthorized access to workflow management and automation services.",
			cwe:         "CWE-798", keywords: []string{"pnu_"},
			remediation: "Imported from Gitleaks: prefect-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-299", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)-----BEGIN[ A-Z0-9_-]{0,100}PRIVATE KEY(?: BLOCK)?-----[\s\S-]{64,}?KEY(?: BLOCK)?-----`,
			description: "Identified a Private Key, which may compromise cryptographic security and sensitive data encryption.",
			cwe:         "CWE-798", keywords: []string{"-----begin"},
			remediation: "Imported from Gitleaks: private-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-300", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:private[_-]?ai)(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{32})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a PrivateAI Token, posing a risk of unauthorized access to AI services and data manipulation.",
			cwe:         "CWE-798", keywords: []string{"privateai", "private_ai", "private-ai"},
			remediation: "Imported from Gitleaks: privateai-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-301", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(pul-[a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Pulumi API token, posing a risk to infrastructure as code services and cloud resource management.",
			cwe:         "CWE-798", keywords: []string{"pul-"},
			remediation: "Imported from Gitleaks: pulumi-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-302", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `pypi-AgEIcHlwaS5vcmc[\w-]{50,1000}`,
			description: "Discovered a PyPI upload token, potentially compromising Python package distribution and repository integrity.",
			cwe:         "CWE-798", keywords: []string{"pypi-ageichlwas5vcmc"},
			remediation: "Imported from Gitleaks: pypi-upload-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-303", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:rapidapi)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9_-]{50})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a RapidAPI Access Token, which could lead to unauthorized access to various APIs and data services.",
			cwe:         "CWE-798", keywords: []string{"rapidapi"},
			remediation: "Imported from Gitleaks: rapidapi-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-304", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(rdme_[a-z0-9]{70})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Readme API token, risking unauthorized documentation management and content exposure.",
			cwe:         "CWE-798", keywords: []string{"rdme_"},
			remediation: "Imported from Gitleaks: readme-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-305", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(rubygems_[a-f0-9]{48})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Rubygem API token, potentially compromising Ruby library distribution and package management.",
			cwe:         "CWE-798", keywords: []string{"rubygems_"},
			remediation: "Imported from Gitleaks: rubygems-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-306", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(tk-us-[\w-]{48})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Scalingo API token, posing a risk to cloud platform services and application deployment security.",
			cwe:         "CWE-798", keywords: []string{"tk-us-"},
			remediation: "Imported from Gitleaks: scalingo-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-307", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Sendbird Access ID, which could compromise chat and messaging platform integrations.",
			cwe:         "CWE-798", keywords: []string{"sendbird"},
			remediation: "Imported from Gitleaks: sendbird-access-id",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-308", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:sendbird)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Sendbird Access Token, potentially risking unauthorized access to communication services and user data.",
			cwe:         "CWE-798", keywords: []string{"sendbird"},
			remediation: "Imported from Gitleaks: sendbird-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-309", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(SG\.(?i)[a-z0-9=_\-\.]{66})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a SendGrid API token, posing a risk of unauthorized email service operations and data exposure.",
			cwe:         "CWE-798", keywords: []string{"sg."},
			remediation: "Imported from Gitleaks: sendgrid-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-310", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(xkeysib-[a-f0-9]{64}\-(?i)[a-z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Sendinblue API token, which may compromise email marketing services and subscriber data privacy.",
			cwe:         "CWE-798", keywords: []string{"xkeysib-"},
			remediation: "Imported from Gitleaks: sendinblue-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-311", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:sentry)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Sentry.io Access Token (old format), risking unauthorized access to error tracking services and sensitive application data.",
			cwe:         "CWE-798", keywords: []string{"sentry"},
			remediation: "Imported from Gitleaks: sentry-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-312", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\bsntrys_eyJpYXQiO[a-zA-Z0-9+/]{10,200}(?:LCJyZWdpb25fdXJs|InJlZ2lvbl91cmwi|cmVnaW9uX3VybCI6)[a-zA-Z0-9+/]{10,200}={0,2}_[a-zA-Z0-9+/]{43}(?:[^a-zA-Z0-9+/]|\z)`,
			description: "Found a Sentry.io Organization Token, risking unauthorized access to error tracking services and sensitive application data.",
			cwe:         "CWE-798", keywords: []string{"sntrys_eyjpyxqio"},
			remediation: "Imported from Gitleaks: sentry-org-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-313", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(sntryu_[a-f0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Sentry.io User Token, risking unauthorized access to error tracking services and sensitive application data.",
			cwe:         "CWE-798", keywords: []string{"sntryu_"},
			remediation: "Imported from Gitleaks: sentry-user-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-314", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(sm_aat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Settlemint Application Access Token.",
			cwe:         "CWE-798", keywords: []string{"sm_aat"},
			remediation: "Imported from Gitleaks: settlemint-application-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-315", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(sm_pat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Settlemint Personal Access Token.",
			cwe:         "CWE-798", keywords: []string{"sm_pat"},
			remediation: "Imported from Gitleaks: settlemint-personal-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-316", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(sm_sat_[a-zA-Z0-9]{16})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Settlemint Service Access Token.",
			cwe:         "CWE-798", keywords: []string{"sm_sat"},
			remediation: "Imported from Gitleaks: settlemint-service-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-317", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(shippo_(?:live|test)_[a-fA-F0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Shippo API token, potentially compromising shipping services and customer order data.",
			cwe:         "CWE-798", keywords: []string{"shippo_"},
			remediation: "Imported from Gitleaks: shippo-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-318", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `shpat_[a-fA-F0-9]{32}`,
			description: "Uncovered a Shopify access token, which could lead to unauthorized e-commerce platform access and data breaches.",
			cwe:         "CWE-798", keywords: []string{"shpat_"},
			remediation: "Imported from Gitleaks: shopify-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-319", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `shpca_[a-fA-F0-9]{32}`,
			description: "Detected a Shopify custom access token, potentially compromising custom app integrations and e-commerce data security.",
			cwe:         "CWE-798", keywords: []string{"shpca_"},
			remediation: "Imported from Gitleaks: shopify-custom-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-320", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `shppa_[a-fA-F0-9]{32}`,
			description: "Identified a Shopify private app access token, risking unauthorized access to private app data and store operations.",
			cwe:         "CWE-798", keywords: []string{"shppa_"},
			remediation: "Imported from Gitleaks: shopify-private-app-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-321", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `shpss_[a-fA-F0-9]{32}`,
			description: "Found a Shopify shared secret, posing a risk to application authentication and e-commerce platform security.",
			cwe:         "CWE-798", keywords: []string{"shpss_"},
			remediation: "Imported from Gitleaks: shopify-shared-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-322", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:BUNDLE_ENTERPRISE__CONTRIBSYS__COM|BUNDLE_GEMS__CONTRIBSYS__COM)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-f0-9]{8}:[a-f0-9]{8})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Sidekiq Secret, which could lead to compromised background job processing and application data breaches.",
			cwe:         "CWE-798", keywords: []string{"bundle_enterprise__contribsys__com", "bundle_gems__contribsys__com"},
			remediation: "Imported from Gitleaks: sidekiq-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-323", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\bhttps?://([a-f0-9]{8}:[a-f0-9]{8})@(?:gems.contribsys.com|enterprise.contribsys.com)(?:[\/|\#|\?|:]|$)`,
			description: "Uncovered a Sidekiq Sensitive URL, potentially exposing internal job queues and sensitive operation details.",
			cwe:         "CWE-798", keywords: []string{"gems.contribsys.com", "enterprise.contribsys.com"},
			remediation: "Imported from Gitleaks: sidekiq-sensitive-url",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-324", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)xapp-\d-[A-Z0-9]+-\d+-[a-z0-9]+`,
			description: "Detected a Slack App-level token, risking unauthorized access to Slack applications and workspace data.",
			cwe:         "CWE-798", keywords: []string{"xapp"},
			remediation: "Imported from Gitleaks: slack-app-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-325", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `xoxb-[0-9]{10,13}-[0-9]{10,13}[a-zA-Z0-9-]*`,
			description: "Identified a Slack Bot token, which may compromise bot integrations and communication channel security.",
			cwe:         "CWE-798", keywords: []string{"xoxb"},
			remediation: "Imported from Gitleaks: slack-bot-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-326", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)xoxe.xox[bp]-\d-[A-Z0-9]{163,166}`,
			description: "Found a Slack Configuration access token, posing a risk to workspace configuration and sensitive data access.",
			cwe:         "CWE-798", keywords: []string{"xoxe.xoxb-", "xoxe.xoxp-"},
			remediation: "Imported from Gitleaks: slack-config-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-327", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)xoxe-\d-[A-Z0-9]{146}`,
			description: "Discovered a Slack Configuration refresh token, potentially allowing prolonged unauthorized access to configuration settings.",
			cwe:         "CWE-798", keywords: []string{"xoxe-"},
			remediation: "Imported from Gitleaks: slack-config-refresh-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-328", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `xoxb-[0-9]{8,14}-[a-zA-Z0-9]{18,26}`,
			description: "Uncovered a Slack Legacy bot token, which could lead to compromised legacy bot operations and data exposure.",
			cwe:         "CWE-798", keywords: []string{"xoxb"},
			remediation: "Imported from Gitleaks: slack-legacy-bot-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-329", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `xox[os]-\d+-\d+-\d+-[a-fA-F\d]+`,
			description: "Detected a Slack Legacy token, risking unauthorized access to older Slack integrations and user data.",
			cwe:         "CWE-798", keywords: []string{"xoxo", "xoxs"},
			remediation: "Imported from Gitleaks: slack-legacy-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-330", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `xox[ar]-(?:\d-)?[0-9a-zA-Z]{8,48}`,
			description: "Identified a Slack Legacy Workspace token, potentially compromising access to workspace data and legacy features.",
			cwe:         "CWE-798", keywords: []string{"xoxa", "xoxr"},
			remediation: "Imported from Gitleaks: slack-legacy-workspace-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-331", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `xox[pe](?:-[0-9]{10,13}){3}-[a-zA-Z0-9-]{28,34}`,
			description: "Found a Slack User token, posing a risk of unauthorized user impersonation and data access within Slack workspaces.",
			cwe:         "CWE-798", keywords: []string{"xoxp-", "xoxe-"},
			remediation: "Imported from Gitleaks: slack-user-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-332", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?:https?://)?hooks.slack.com/(?:services|workflows|triggers)/[A-Za-z0-9+/]{43,56}`,
			description: "Discovered a Slack Webhook, which could lead to unauthorized message posting and data leakage in Slack channels.",
			cwe:         "CWE-798", keywords: []string{"hooks.slack.com"},
			remediation: "Imported from Gitleaks: slack-webhook-url",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-333", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:snyk[_.-]?(?:(?:api|oauth)[_.-]?)?(?:key|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Snyk API token, potentially compromising software vulnerability scanning and code security.",
			cwe:         "CWE-798", keywords: []string{"snyk"},
			remediation: "Imported from Gitleaks: snyk-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-334", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:sonar[_.-]?(login|token))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}((?:squ_|sqp_|sqa_)?[a-z0-9=_\-]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Sonar API token, potentially compromising software vulnerability scanning and code security.",
			cwe:         "CWE-798", keywords: []string{"sonar"},
			remediation: "Imported from Gitleaks: sonar-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-335", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)\b(\b(sgp_(?:[a-fA-F0-9]{16}|local)_[a-fA-F0-9]{40}|sgp_[a-fA-F0-9]{40}|[a-fA-F0-9]{40})\b)(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Sourcegraph is a code search and navigation engine.",
			cwe:         "CWE-798", keywords: []string{"sgp_", "sourcegraph"},
			remediation: "Imported from Gitleaks: sourcegraph-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-336", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b((?:EAAA|sq0atp-)[\w-]{22,60})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Square Access Token, risking unauthorized payment processing and financial transaction exposure.",
			cwe:         "CWE-798", keywords: []string{"sq0atp-", "eaaa"},
			remediation: "Imported from Gitleaks: square-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-337", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:squarespace)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Squarespace Access Token, which may compromise website management and content control on Squarespace.",
			cwe:         "CWE-798", keywords: []string{"squarespace"},
			remediation: "Imported from Gitleaks: squarespace-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-338", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b((?:sk|rk)_(?:test|live|prod)_[a-zA-Z0-9]{10,99})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Stripe Access Token, posing a risk to payment processing services and sensitive financial data.",
			cwe:         "CWE-798", keywords: []string{"sk_test", "sk_live", "sk_prod", "rk_test", "rk_live", "rk_prod"},
			remediation: "Imported from Gitleaks: stripe-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-339", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `[\w.-]{0,50}?(?i:[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s'"]{0,3})(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(su[a-zA-Z0-9]{12})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a SumoLogic Access ID, potentially compromising log management services and data analytics integrity.",
			cwe:         "CWE-798", keywords: []string{"sumo"},
			remediation: "Imported from Gitleaks: sumologic-access-id",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-340", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:(?-i:[Ss]umo|SUMO))(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{64})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a SumoLogic Access Token, which could lead to unauthorized access to log data and analytics insights.",
			cwe:         "CWE-798", keywords: []string{"sumo"},
			remediation: "Imported from Gitleaks: sumologic-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-341", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:telegr)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{5,16}:(?-i:A)[a-z0-9_\-]{34})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Telegram Bot API Token, risking unauthorized bot operations and message interception on Telegram.",
			cwe:         "CWE-798", keywords: []string{"telegr"},
			remediation: "Imported from Gitleaks: telegram-bot-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-342", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:travis)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{22})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Travis CI Access Token, potentially compromising continuous integration services and codebase security.",
			cwe:         "CWE-798", keywords: []string{"travis"},
			remediation: "Imported from Gitleaks: travisci-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-343", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:twitch)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{30})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Twitch API token, which could compromise streaming services and account integrations.",
			cwe:         "CWE-798", keywords: []string{"twitch"},
			remediation: "Imported from Gitleaks: twitch-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-344", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{45})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Twitter Access Secret, potentially risking unauthorized Twitter integrations and data breaches.",
			cwe:         "CWE-798", keywords: []string{"twitter"},
			remediation: "Imported from Gitleaks: twitter-access-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-345", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([0-9]{15,25}-[a-zA-Z0-9]{20,40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Twitter Access Token, posing a risk of unauthorized account operations and social media data exposure.",
			cwe:         "CWE-798", keywords: []string{"twitter"},
			remediation: "Imported from Gitleaks: twitter-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-346", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{25})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Twitter API Key, which may compromise Twitter application integrations and user data security.",
			cwe:         "CWE-798", keywords: []string{"twitter"},
			remediation: "Imported from Gitleaks: twitter-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-347", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{50})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Twitter API Secret, risking the security of Twitter app integrations and sensitive data access.",
			cwe:         "CWE-798", keywords: []string{"twitter"},
			remediation: "Imported from Gitleaks: twitter-api-secret",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-348", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:twitter)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(A{22}[a-zA-Z0-9%]{80,100})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Twitter Bearer Token, potentially compromising API access and data retrieval from Twitter.",
			cwe:         "CWE-798", keywords: []string{"twitter"},
			remediation: "Imported from Gitleaks: twitter-bearer-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-349", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:typeform)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(tfp_[a-z0-9\-_\.=]{59})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Typeform API token, which could lead to unauthorized survey management and data collection.",
			cwe:         "CWE-798", keywords: []string{"tfp_"},
			remediation: "Imported from Gitleaks: typeform-api-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-350", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b(hvb\.[\w-]{138,300})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Vault Batch Token, risking unauthorized access to secret management services and sensitive data.",
			cwe:         "CWE-798", keywords: []string{"hvb."},
			remediation: "Imported from Gitleaks: vault-batch-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-351", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `\b((?:hvs\.[\w-]{90,120}|s\.(?i:[a-z0-9]{24})))(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Identified a Vault Service Token, potentially compromising infrastructure security and access to sensitive credentials.",
			cwe:         "CWE-798", keywords: []string{"hvs.", "s."},
			remediation: "Imported from Gitleaks: vault-service-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-352", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(t1\.[A-Z0-9a-z_-]+[=]{0,2}\.[A-Z0-9a-z_-]{86}[=]{0,2})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Found a Yandex Access Token, posing a risk to Yandex service integrations and user data privacy.",
			cwe:         "CWE-798", keywords: []string{"yandex"},
			remediation: "Imported from Gitleaks: yandex-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-353", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(AQVN[A-Za-z0-9_\-]{35,38})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Discovered a Yandex API Key, which could lead to unauthorized access to Yandex services and data manipulation.",
			cwe:         "CWE-798", keywords: []string{"yandex"},
			remediation: "Imported from Gitleaks: yandex-api-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-354", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:yandex)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}(YC[a-zA-Z0-9_\-]{38})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Uncovered a Yandex AWS Access Token, potentially compromising cloud resource access and data security on Yandex Cloud.",
			cwe:         "CWE-798", keywords: []string{"yandex"},
			remediation: "Imported from Gitleaks: yandex-aws-access-token",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		{
			id: "SEC-355", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:     `(?i)[\w.-]{0,50}?(?:zendesk)(?:[ \t\w.-]{0,20})[\s'"]{0,3}(?:=|>|:{1,3}=|\|\||:|=>|\?=|,)[\x60'"\s=]{0,5}([a-z0-9]{40})(?:[\x60'"\s;]|\\[nr]|$)`,
			description: "Detected a Zendesk Secret Key, risking unauthorized access to customer support services and sensitive ticketing data.",
			cwe:         "CWE-798", keywords: []string{"zendesk"},
			remediation: "Imported from Gitleaks: zendesk-secret-key",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},

		// -----------------------------------------------------------------
		// Additional custom rules (SEC-356 to SEC-410) - Database, JWT, Cloud
		// -----------------------------------------------------------------
		{id: "SEC-356", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `postgresql://[^\s]+`, description: "Detected PostgreSQL connection string", cwe: "CWE-798", keywords: []string{"postgresql"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-357", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `mysql://[^\s]+`, description: "Detected MySQL connection string", cwe: "CWE-798", keywords: []string{"mysql"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-358", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `mariadb://[^\s]+`, description: "Detected MariaDB connection string", cwe: "CWE-798", keywords: []string{"mariadb"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-359", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `mongodb(\+srv)?://[^\s]+`, description: "Detected MongoDB connection string", cwe: "CWE-798", keywords: []string{"mongodb"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-360", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `redis://[^\s]+`, description: "Detected Redis connection string", cwe: "CWE-798", keywords: []string{"redis"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-361", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `rediss://[^\s]+`, description: "Detected Redis SSL connection string", cwe: "CWE-798", keywords: []string{"rediss"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-362", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `Server=[^;]+;.*Password=[^;]+`, description: "Detected MSSQL connection string", cwe: "CWE-798", keywords: []string{"mssql"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-363", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `oracle://[^\s]+`, description: "Detected Oracle connection string", cwe: "CWE-798", keywords: []string{"oracle"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-364", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `sqlite://[^\s]+`, description: "Detected SQLite connection string", cwe: "CWE-798", keywords: []string{"sqlite"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-365", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `cassandra://[^\s]+`, description: "Detected Cassandra connection string", cwe: "CWE-798", keywords: []string{"cassandra"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-366", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `couchdb://[^\s]+`, description: "Detected CouchDB connection string", cwe: "CWE-798", keywords: []string{"couchdb"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-367", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `influxdb://[^\s]+`, description: "Detected InfluxDB connection string", cwe: "CWE-798", keywords: []string{"influxdb"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-368", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `dynamodb://[^\s]+`, description: "Detected DynamoDB connection string", cwe: "CWE-798", keywords: []string{"dynamodb"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-369", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `elasticsearch://[^\s]+`, description: "Detected Elasticsearch connection string", cwe: "CWE-798", keywords: []string{"elasticsearch"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-370", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `solr://[^\s]+`, description: "Detected Solr connection string", cwe: "CWE-798", keywords: []string{"solr"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-371", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+`, description: "Detected JWT token", cwe: "CWE-798", keywords: []string{"jwt"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-372", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `s3\.amazonaws\.com/[^\s]+`, description: "Detected AWS S3 URL", cwe: "CWE-798", keywords: []string{"s3"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-373", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `s3://[^\s]+`, description: "Detected S3 bucket URL", cwe: "CWE-798", keywords: []string{"s3_bucket"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-374", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `storage\.googleapis\.com/[^\s]+`, description: "Detected Google Cloud Storage URL", cwe: "CWE-798", keywords: []string{"gcs"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-375", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `blob\.core\.windows\.net/[^\s]+`, description: "Detected Azure Blob Storage URL", cwe: "CWE-798", keywords: []string{"azure_blob"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-376", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}`, description: "Detected SendGrid API key", cwe: "CWE-798", keywords: []string{"sendgrid"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-377", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `key-[A-Za-z0-9]{32}`, description: "Detected Mailgun API key", cwe: "CWE-798", keywords: []string{"mailgun"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-378", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{32}-us[0-9]{1,2}`, description: "Detected Mailchimp API key", cwe: "CWE-798", keywords: []string{"mailchimp"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-379", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `AC[a-z0-9]{32}`, description: "Detected Twilio Account SID", cwe: "CWE-798", keywords: []string{"twilio_sid"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-380", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{16}`, description: "Detected Nexmo API key", cwe: "CWE-798", keywords: []string{"nexmo"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-381", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `plaid[_-]?key[_-]?[^\s]{20,40}`, description: "Detected Plaid API key", cwe: "CWE-798", keywords: []string{"plaid"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-382", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `sq0csp-[A-Za-z0-9_-]{43}`, description: "Detected Square API key", cwe: "CWE-798", keywords: []string{"square"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-383", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `shpat_[a-f0-9]{32}`, description: "Detected Shopify API key", cwe: "CWE-798", keywords: []string{"shopify"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-384", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Braintree API key", cwe: "CWE-798", keywords: []string{"braintree"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-385", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `api[_-]?secret\s*[=:]\s*['\"][A-Za-z0-9_-]{20,}['\"]`, description: "Detected Generic API Secret", cwe: "CWE-798", keywords: []string{"api_secret"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-386", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `access[_-]?token\s*[=:]\s*['\"][A-Za-z0-9_-]{20,}['\"]`, description: "Detected Generic Access Token", cwe: "CWE-798", keywords: []string{"access_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-387", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `refresh[_-]?token\s*[=:]\s*['\"][A-Za-z0-9_-]{20,}['\"]`, description: "Detected Generic Refresh Token", cwe: "CWE-798", keywords: []string{"refresh_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-388", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `bearer\s+[A-Za-z0-9_-]{20,}`, description: "Detected Bearer Token", cwe: "CWE-798", keywords: []string{"bearer_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-389", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `authorization\s*:\s*[A-Za-z0-9_-]{20,}`, description: "Detected Authorization Header", cwe: "CWE-798", keywords: []string{"authorization"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-390", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN (RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----`, description: "Detected Private Key", cwe: "CWE-798", keywords: []string{"private_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-391", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN OPENSSH PRIVATE KEY-----`, description: "Detected OpenSSH Private Key", cwe: "CWE-798", keywords: []string{"openssh_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-392", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN PGP PRIVATE KEY BLOCK-----`, description: "Detected PGP Private Key", cwe: "CWE-798", keywords: []string{"pgp_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-393", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `dd_api_key=[a-z0-9]{32}`, description: "Detected Datadog API Key", cwe: "CWE-798", keywords: []string{"datadog"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-394", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `dd_app_key=[a-z0-9]{40}`, description: "Detected Datadog App Key", cwe: "CWE-798", keywords: []string{"datadog_app"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-395", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{40}`, description: "Detected New Relic API Key", cwe: "CWE-798", keywords: []string{"newrelic"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-396", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `https://[a-z0-9]{32}@sentry\.io/[0-9]+`, description: "Detected Sentry DSN", cwe: "CWE-798", keywords: []string{"sentry"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-397", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Honeybadger API Key", cwe: "CWE-798", keywords: []string{"honeybadger"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-398", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Rollbar Access Token", cwe: "CWE-798", keywords: []string{"rollbar"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-399", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{32}`, description: "Detected Bugsnag API Key", cwe: "CWE-798", keywords: []string{"bugsnag"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-400", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `circleci[_-]?token[_-]?[^\s]{20,}`, description: "Detected CircleCI API Token", cwe: "CWE-798", keywords: []string{"circleci"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-401", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `travis[_-]?token[_-]?[^\s]{20,}`, description: "Detected Travis CI API Token", cwe: "CWE-798", keywords: []string{"travis"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-402", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, description: "Detected Heroku API Key", cwe: "CWE-798", keywords: []string{"heroku_api"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-403", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `grafana[_-]?api[_-]?key[^\s]{20,}`, description: "Detected Grafana API Key", cwe: "CWE-798", keywords: []string{"grafana"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-404", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `prometheus[_-]?api[_-]?key[^\s]{20,}`, description: "Detected Prometheus API Key", cwe: "CWE-798", keywords: []string{"prometheus"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-405", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `kibana[_-]?password[^\s]{20,}`, description: "Detected Kibana Password", cwe: "CWE-798", keywords: []string{"kibana"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-406", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `jupyter[_-]?token[^\s]{20,}`, description: "Detected Jupyter Token", cwe: "CWE-798", keywords: []string{"jupyter"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-407", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `kubernetes[_-]?token[^\s]{40,}`, description: "Detected Kubernetes Service Account Token", cwe: "CWE-798", keywords: []string{"kubernetes_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-408", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `npm_[A-Za-z0-9]{36}`, description: "Detected NPM Access Token", cwe: "CWE-798", keywords: []string{"npm_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-409", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `pypi-AgEI[a-zA-Z0-9_-]{50,}`, description: "Detected PyPI API Token", cwe: "CWE-798", keywords: []string{"pypi_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-410", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `_json_key`, description: "Detected Google Container Registry Key", cwe: "CWE-798", keywords: []string{"gcr_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},

		// -----------------------------------------------------------------
		// Extended rules (SEC-411 to SEC-441) - AWS, GCP, Azure, OAuth, Keys
		// -----------------------------------------------------------------
		{id: "SEC-411", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `AKIA[0-9A-Z]{16}`, description: "Detected AWS Access Key", cwe: "CWE-798", keywords: []string{"aws_access"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-412", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `aws.{0,20}?["'][0-9a-zA-Z\/+]{40}["']`, description: "Detected AWS Secret", cwe: "CWE-798", keywords: []string{"aws_secret"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-413", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `s3\.amazonaws`, description: "Detected AWS S3", cwe: "CWE-798", keywords: []string{"aws_s3"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-414", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:rds`, description: "Detected AWS RDS", cwe: "CWE-798", keywords: []string{"aws_rds"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-415", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `AIza[0-9A-Za-z\-_]{35}`, description: "Detected GCP API Key", cwe: "CWE-798", keywords: []string{"gcp_api"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-416", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `service_account`, description: "Detected GCP Service Account", cwe: "CWE-798", keywords: []string{"gcp_sa"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-417", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `gs://`, description: "Detected GCP Bucket", cwe: "CWE-798", keywords: []string{"gcp_bucket"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-418", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `clusters/`, description: "Detected GKE Cluster", cwe: "CWE-798", keywords: []string{"gke"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-419", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `/subscriptions/`, description: "Detected Azure Subscription", cwe: "CWE-798", keywords: []string{"azure_sub"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-420", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `/tenants/`, description: "Detected Azure Tenant", cwe: "CWE-798", keywords: []string{"azure_tenant"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-421", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`, description: "Detected Azure Client ID", cwe: "CWE-798", keywords: []string{"azure_client"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-422", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `vault\.azure\.net`, description: "Detected Azure Key Vault", cwe: "CWE-798", keywords: []string{"azure_keyvault"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-423", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `ya29\.`, description: "Detected Google OAuth", cwe: "CWE-798", keywords: []string{"google_oauth"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-424", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `EAACEdEose0cBA`, description: "Detected Facebook OAuth", cwe: "CWE-798", keywords: []string{"fb_oauth"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-425", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `login\.microsoftonline`, description: "Detected Microsoft OAuth", cwe: "CWE-798", keywords: []string{"ms_oauth"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-426", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN RSA PRIVATE KEY-----`, description: "Detected RSA Private Key", cwe: "CWE-798", keywords: []string{"rsa_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-427", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN EC PRIVATE KEY-----`, description: "Detected EC Private Key", cwe: "CWE-798", keywords: []string{"ec_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-428", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN OPENSSH PRIVATE KEY-----`, description: "Detected OpenSSH Key", cwe: "CWE-798", keywords: []string{"openssh_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-429", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN PGP PRIVATE KEY BLOCK-----`, description: "Detected PGP Key", cwe: "CWE-798", keywords: []string{"pgp_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-430", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `postgres://`, description: "Detected PostgreSQL", cwe: "CWE-798", keywords: []string{"postgres"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-431", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `mysql://`, description: "Detected MySQL", cwe: "CWE-798", keywords: []string{"mysql"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-432", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `mongodb(\+srv)?://`, description: "Detected MongoDB", cwe: "CWE-798", keywords: []string{"mongo"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-433", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `redis://`, description: "Detected Redis", cwe: "CWE-798", keywords: []string{"redis"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-434", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `bootstrap\.servers`, description: "Detected Kafka", cwe: "CWE-798", keywords: []string{"kafka"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-435", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `gh[pousr]_[A-Za-z0-9_]`, description: "Detected GitHub Token", cwe: "CWE-798", keywords: []string{"github"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-436", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `glpat-`, description: "Detected GitLab Token", cwe: "CWE-798", keywords: []string{"gitlab"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-437", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `xox[baprs]-`, description: "Detected Slack Token", cwe: "CWE-798", keywords: []string{"slack"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-438", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `sk_live_`, description: "Detected Stripe Key", cwe: "CWE-798", keywords: []string{"stripe"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-439", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `SG\.`, description: "Detected SendGrid Key", cwe: "CWE-798", keywords: []string{"sendgrid"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-440", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `key-[0-9a-zA-Z]{32}`, description: "Detected Mailgun Key", cwe: "CWE-798", keywords: []string{"mailgun"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},

		// -----------------------------------------------------------------
		// More service rules (SEC-442 to SEC-492) - SaaS, DevTools, Infrastructure
		// -----------------------------------------------------------------
		{id: "SEC-442", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `secret_[a-zA-Z0-9]{43}`, description: "Detected Notion API Key", cwe: "CWE-798", keywords: []string{"notion"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-443", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `lin_api_[a-zA-Z0-9]{43}`, description: "Detected Linear API Key", cwe: "CWE-798", keywords: []string{"linear"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-444", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `vercel_[a-zA-Z0-9]{24,}`, description: "Detected Vercel API Key", cwe: "CWE-798", keywords: []string{"vercel"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-445", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `nf-[a-zA-Z0-9]{22,43}`, description: "Detected Netlify API Key", cwe: "CWE-798", keywords: []string{"netlify"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-446", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9_-]{37,43}`, description: "Detected Cloudflare API Key", cwe: "CWE-798", keywords: []string{"cloudflare"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-447", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `DD[a-zA-Z]{20,}`, description: "Detected Datadog API Key", cwe: "CWE-798", keywords: []string{"datadog"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-448", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `https://[a-z0-9]{32}@`, description: "Detected Sentry DSN", cwe: "CWE-798", keywords: []string{"sentry"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-449", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `eu01xx[a-f0-9]{32}`, description: "Detected New Relic License Key", cwe: "CWE-798", keywords: []string{"newrelic"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-450", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `1/[a-z0-9]{32}`, description: "Detected LogRocket API Key", cwe: "CWE-798", keywords: []string{"logrocket"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-451", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{32}`, description: "Detected Bugsnag API Key", cwe: "CWE-798", keywords: []string{"bugsnag"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-452", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Rollbar Access Token", cwe: "CWE-798", keywords: []string{"rollbar"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-453", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Mixpanel API Key", cwe: "CWE-798", keywords: []string{"mixpanel"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-454", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Amplitude API Key", cwe: "CWE-798", keywords: []string{"amplitude"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-455", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Segment API Key", cwe: "CWE-798", keywords: []string{"segment"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-456", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Braze API Key", cwe: "CWE-798", keywords: []string{"braze"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-457", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected Iterable API Key", cwe: "CWE-798", keywords: []string{"iterable"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-458", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `pk_[a-z0-9]{32}`, description: "Detected Klaviyo API Key", cwe: "CWE-798", keywords: []string{"klaviyo"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-459", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `xkeys-[a-z0-9-]{32,}`, description: "Detected Sendinblue API Key", cwe: "CWE-798", keywords: []string{"sendinblue"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-460", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected CleverReach API Key", cwe: "CWE-798", keywords: []string{"cleverreach"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-461", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `amqp://`, description: "Detected AMQP Connection URL", cwe: "CWE-798", keywords: []string{"amqp"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-462", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `smtp://`, description: "Detected SMTP Connection URL", cwe: "CWE-798", keywords: []string{"smtp"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-463", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `ssh-rsa AAAA`, description: "Detected SSH Key", cwe: "CWE-798", keywords: []string{"ssh"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-464", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `-----BEGIN PGP PUBLIC KEY BLOCK-----`, description: "Detected PGP Public Key", cwe: "CWE-798", keywords: []string{"gpg"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-465", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:iam::`, description: "Detected AWS IAM ARN", cwe: "CWE-798", keywords: []string{"aws_iam"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-466", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:secretsmanager:`, description: "Detected AWS Secrets Manager ARN", cwe: "CWE-798", keywords: []string{"aws_secret"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-467", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `projects/[a-z0-9-]+/serviceAccounts/`, description: "Detected GCP Service Account", cwe: "CWE-798", keywords: []string{"gcp_iam"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-468", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `kubectl create secret generic`, description: "Detected Kubernetes Secret", cwe: "CWE-798", keywords: []string{"k8s_secret"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-469", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `TOKEN=|API_KEY=|SECRET=`, description: "Detected Environment Variable Secret", cwe: "CWE-798", keywords: []string{"env_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-470", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}`, description: "Detected Heroku API Key", cwe: "CWE-798", keywords: []string{"heroku_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-471", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{64}`, description: "Detected DigitalOcean Token", cwe: "CWE-798", keywords: []string{"digitalocean_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-472", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[A-Za-z0-9_-]{64}`, description: "Detected Linode Token", cwe: "CWE-798", keywords: []string{"linode_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-473", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[A-Za-z0-9_-]{36}`, description: "Detected Vultr API Token", cwe: "CWE-798", keywords: []string{"vultr_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-474", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `0042[a-z0-9]{14}`, description: "Detected Backblaze Key ID", cwe: "CWE-798", keywords: []string{"backblaze_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-475", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{60}`, description: "Detected Backblaze Secret Key", cwe: "CWE-798", keywords: []string{"backblaze_secret"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-476", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9_-]{32}`, description: "Detected Fastly API Token", cwe: "CWE-798", keywords: []string{"fastly_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-477", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9_-]{50,}`, description: "Detected Akamai API Token", cwe: "CWE-798", keywords: []string{"akamai_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-478", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9_-]{32,}`, description: "Detected Auth0 Token", cwe: "CWE-798", keywords: []string{"auth0_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-479", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9_-]{42}`, description: "Detected Okta API Token", cwe: "CWE-798", keywords: []string{"okta_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-480", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{20}`, description: "Detected PagerDuty API Key", cwe: "CWE-798", keywords: []string{"pagerduty_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-481", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected Typeform API Key", cwe: "CWE-798", keywords: []string{"typeform_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-482", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9_-]{32,}`, description: "Detected Webflow API Key", cwe: "CWE-798", keywords: []string{"webflow_key"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-483", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `sk[a-zA-Z0-9]{32,}`, description: "Detected Sanity API Token", cwe: "CWE-798", keywords: []string{"sanity_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-484", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{24}`, description: "Detected Ghost Admin API Key", cwe: "CWE-798", keywords: []string{"ghost_token"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},

		// -----------------------------------------------------------------
		// CI/CD, Package Managers, Cloud Providers (SEC-493 to SEC-549)
		// -----------------------------------------------------------------
		{id: "SEC-493", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `ccb_[a-zA-Z0-9]{32,}`, description: "Detected CircleCI API Token", cwe: "CWE-798", keywords: []string{"circleci"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-494", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected Travis CI API Token", cwe: "CWE-798", keywords: []string{"travisci"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-495", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `gho_[a-zA-Z0-9]{36}`, description: "Detected GitHub OAuth Token", cwe: "CWE-798", keywords: []string{"github"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-496", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `ghp_[a-zA-Z0-9]{36}`, description: "Detected GitHub Personal Access Token", cwe: "CWE-798", keywords: []string{"github"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-497", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `ghr_[a-zA-Z0-9]{36}`, description: "Detected GitHub Refresh Token", cwe: "CWE-798", keywords: []string{"github"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-498", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `xoxb-[a-zA-Z0-9-]{24,}`, description: "Detected Slack Bot Token", cwe: "CWE-798", keywords: []string{"slack"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-499", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `xoxp-[a-zA-Z0-9-]{24,}`, description: "Detected Slack User Token", cwe: "CWE-798", keywords: []string{"slack"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-500", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `bitbucket_token[a-zA-Z0-9_-]{32,}`, description: "Detected Bitbucket Token", cwe: "CWE-798", keywords: []string{"bitbucket"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-501", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `ATBB[a-zA-Z0-9]{32,}`, description: "Detected Bitbucket App Password", cwe: "CWE-798", keywords: []string{"bitbucket"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-502", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `npm_[a-zA-Z0-9]{36}`, description: "Detected NPM Access Token", cwe: "CWE-798", keywords: []string{"npm"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-503", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `pypi-AgEIcHlwaS5vcmc[A-Za-z0-9-_]{50,}`, description: "Detected PyPI API Token", cwe: "CWE-798", keywords: []string{"pypi"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-504", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `rubygems_[a-zA-Z0-9]{48}`, description: "Detected RubyGems API Token", cwe: "CWE-798", keywords: []string{"rubygems"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-505", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{36}`, description: "Detected Maven Repository Token", cwe: "CWE-798", keywords: []string{"maven"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-506", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected NuGet API Key", cwe: "CWE-798", keywords: []string{"nuget"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		// SEC-507 removed: pattern too generic (matched comment separators)
		{id: "SEC-508", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `AKIA[0-9A-Z]{16}`, description: "Detected AWS Access Key ID (alternate)", cwe: "CWE-798", keywords: []string{"aws"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-509", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `ASIA[0-9A-Z]{16}`, description: "Detected AWS Temporary Access Key ID", cwe: "CWE-798", keywords: []string{"aws"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-510", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[0-9a-zA-Z/+]{40}`, description: "Detected AWS Secret Access Key (alternate)", cwe: "CWE-798", keywords: []string{"aws_secret"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-511", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:ecs:`, description: "Detected AWS ECS Task Definition ARN", cwe: "CWE-798", keywords: []string{"aws_ecs"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-512", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:lambda:`, description: "Detected AWS Lambda Function ARN", cwe: "CWE-798", keywords: []string{"aws_lambda"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-513", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:s3:::`, description: "Detected AWS S3 Bucket ARN", cwe: "CWE-798", keywords: []string{"aws_s3"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-514", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:rds:`, description: "Detected AWS RDS Instance ARN", cwe: "CWE-798", keywords: []string{"aws_rds"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-515", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:ec2:`, description: "Detected AWS EC2 Instance ARN", cwe: "CWE-798", keywords: []string{"aws_ec2"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-516", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:iam::\d+:role/`, description: "Detected AWS IAM Role ARN", cwe: "CWE-798", keywords: []string{"aws_iam_role"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-517", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:dynamodb:`, description: "Detected AWS DynamoDB Table ARN", cwe: "CWE-798", keywords: []string{"aws_dynamodb"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-518", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:sqs:`, description: "Detected AWS SQS Queue ARN", cwe: "CWE-798", keywords: []string{"aws_sqs"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-519", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `arn:aws:snq:`, description: "Detected AWS SNS Topic ARN", cwe: "CWE-798", keywords: []string{"aws_sns"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-520", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `projects/[a-z0-9-]+/locations/`, description: "Detected GCP Resource Location", cwe: "CWE-798", keywords: []string{"gcp"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-521", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `https://container.googleapis.com/v1/projects/`, description: "Detected GKE Cluster URL", cwe: "CWE-798", keywords: []string{"gcp_gke"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-522", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `https://storage.googleapis.com/`, description: "Detected GCS Bucket URL", cwe: "CWE-798", keywords: []string{"gcp_storage"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-523", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `/subscriptions/[a-z0-9-]+/resourceGroups/`, description: "Detected Azure Resource ID", cwe: "CWE-798", keywords: []string{"azure"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-524", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32,}`, description: "Detected Azure Subscription ID", cwe: "CWE-798", keywords: []string{"azure_sub"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-525", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected DigitalOcean API Key (alternate)", cwe: "CWE-798", keywords: []string{"digitalocean"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-526", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `do_[a-z0-9]{32}`, description: "Detected DigitalOcean OAuth Token", cwe: "CWE-798", keywords: []string{"digitalocean_oauth"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-527", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[A-Za-z0-9_-]{64}`, description: "Detected Scaleway API Token", cwe: "CWE-798", keywords: []string{"scaleway"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-528", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected OVH API Key", cwe: "CWE-798", keywords: []string{"ovh"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-529", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected Aliyun Access Key ID", cwe: "CWE-798", keywords: []string{"aliyun"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-530", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{30}`, description: "Detected Huawei Cloud Access Key", cwe: "CWE-798", keywords: []string{"huawei"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-531", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `AKTP[a-zA-Z0-9_-]{34}`, description: "Detected Tencent Cloud Secret ID", cwe: "CWE-798", keywords: []string{"tencent"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-532", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `oraclecloud.com/`, description: "Detected Oracle Cloud Resource URL", cwe: "CWE-798", keywords: []string{"oracle"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-533", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9_-]{44}`, description: "Detected IBM Cloud API Key", cwe: "CWE-798", keywords: []string{"ibm"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-534", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `https://bj-core\.baiducloud\.com`, description: "Detected Baidu Cloud Endpoint", cwe: "CWE-798", keywords: []string{"baidu"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-535", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `https://\w+\.jdcloud.com`, description: "Detected JD Cloud Endpoint", cwe: "CWE-798", keywords: []string{"jd"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-536", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected Fastly API Token (alternate)", cwe: "CWE-798", keywords: []string{"fastly"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-537", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9-]{32}`, description: "Detected KeyCDN API Key", cwe: "CWE-798", keywords: []string{"keycdn"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-538", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `bunny_[a-zA-Z0-9-]{32,}`, description: "Detected Bunny.net API Key", cwe: "CWE-798", keywords: []string{"bunny"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-539", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-z0-9]{32}`, description: "Detected DNSimple API Token", cwe: "CWE-798", keywords: []string{"dnsimple"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-540", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected Namecheap API Key", cwe: "CWE-798", keywords: []string{"namecheap"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-541", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9@#$%^&*]{16,}`, description: "Detected GoDaddy API Key", cwe: "CWE-798", keywords: []string{"godaddy"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-542", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32,}`, description: "Detected Cloudflare API Token (alternate)", cwe: "CWE-798", keywords: []string{"cloudflare"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-543", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected Datadog API Key (alternate)", cwe: "CWE-798", keywords: []string{"datadog"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-544", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-f0-9]{32}`, description: "Detected New Relic License Key (alternate)", cwe: "CWE-798", keywords: []string{"newrelic"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-545", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{20}`, description: "Detected PagerDuty API Key (alternate)", cwe: "CWE-798", keywords: []string{"pagerduty"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-546", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `[a-zA-Z0-9]{32}`, description: "Detected Sentry DSN (alternate)", cwe: "CWE-798", keywords: []string{"sentry"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-547", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `sk_test_[a-zA-Z0-9]{24}`, description: "Detected Stripe Test API Key", cwe: "CWE-798", keywords: []string{"stripe_test"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-548", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `sk_live_[a-zA-Z0-9]{24}`, description: "Detected Stripe Live API Key", cwe: "CWE-798", keywords: []string{"stripe_live"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
		{id: "SEC-549", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium, pattern: `rk_live_[a-zA-Z0-9]{24}`, description: "Detected Stripe Restricted Key", cwe: "CWE-798", keywords: []string{"stripe_restricted"}, remediation: "Rotate the exposed credential immediately", references: []string{"https://cwe.mitre.org/data/definitions/798.html"}},
	}

	out := make([]*rules.Rule, 0, len(defs)+len(builtinEntropyRules()))
	for i := range defs {
		d := &defs[i]
		out = append(out, &rules.Rule{
			ID:          d.id,
			Version:     "1.0",
			Description: d.description,
			Severity:    d.severity,
			Confidence:  d.confidence,
			MatcherType: "regex",
			Pattern:     d.pattern,
			Keywords:    d.keywords,
			Tags:        []string{"secrets"},
			Metadata:    map[string]string{"cwe": d.cwe},
			Remediation: d.remediation,
			References:  d.references,
		})
	}
	out = append(out, builtinEntropyRules()...)
	return out
}

// entropySourceFilePatterns restricts entropy rules to source-like files,
// excluding lockfiles, checksums, and generated files that produce massive
// numbers of false positives.
var entropySourceFilePatterns = []string{
	"*.go", "*.py", "*.js", "*.ts", "*.jsx", "*.tsx",
	"*.java", "*.kt", "*.rb", "*.php", "*.rs", "*.c", "*.cpp", "*.h",
	"*.cs", "*.swift", "*.sh", "*.bash", "*.zsh",
	"*.yaml", "*.yml", "*.json", "*.toml", "*.ini", "*.cfg", "*.conf",
	"*.env", "*.env.*", ".env", ".env.*",
	"*.xml", "*.properties", "*.gradle",
	"Dockerfile", "docker-compose.yml", "docker-compose.yaml",
	"Makefile", "*.mk",
}

// builtinEntropyRules returns entropy-based secret detection rules. These
// use the "entropy" matcher type and do not require a regex pattern.
// Instead, they rely on Shannon entropy analysis with context-aware
// thresholds to detect high-randomness strings that look like secrets.
func builtinEntropyRules() []*rules.Rule {
	return []*rules.Rule{
		{
			ID:           "SEC-161",
			Version:      "1.1",
			Description:  "High-entropy string in assignment (possible secret)",
			Severity:     findings.SeverityMedium,
			Confidence:   findings.ConfidenceMedium,
			MatcherType:  "entropy",
			Keywords:     []string{"=", ":", "password", "secret", "key", "token", "credential", "api_key", "private"},
			FilePatterns: entropySourceFilePatterns,
			Tags:         []string{"secrets", "entropy"},
			Metadata:     map[string]string{"cwe": "CWE-798", "entropy_threshold": "5.0"},
			Remediation:  "Move high-entropy values to environment variables or a secrets manager. Never hard-code secrets in source files.",
			References:   []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			ID:           "SEC-162",
			Version:      "1.1",
			Description:  "High-entropy base64 blob detected (possible encoded secret)",
			Severity:     findings.SeverityMedium,
			Confidence:   findings.ConfidenceLow,
			MatcherType:  "entropy",
			Keywords:     []string{"password", "secret", "key", "token", "credential", "api_key", "private", "auth"},
			FilePatterns: entropySourceFilePatterns,
			Tags:         []string{"secrets", "entropy"},
			Metadata:     map[string]string{"cwe": "CWE-798", "entropy_threshold": "5.2", "require_context": "true"},
			Remediation:  "Inspect this base64-encoded value. If it contains a secret, move it to a secrets manager.",
			References:   []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			ID:           "SEC-163",
			Version:      "1.1",
			Description:  "High-entropy hex string detected (possible secret key)",
			Severity:     findings.SeverityMedium,
			Confidence:   findings.ConfidenceLow,
			MatcherType:  "entropy",
			Keywords:     []string{"key", "secret", "token", "password", "credential", "private", "auth"},
			FilePatterns: entropySourceFilePatterns,
			Tags:         []string{"secrets", "entropy"},
			Metadata:     map[string]string{"cwe": "CWE-798", "entropy_threshold": "4.5", "require_context": "true"},
			Remediation:  "Review this hex string. If it represents a cryptographic key or secret, move it to a secrets manager.",
			References:   []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
	}
}
