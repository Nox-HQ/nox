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
func builtinSecretRules() []rules.Rule {
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
			pattern:     `(?i)(mysql|postgres(?:ql)?|mssql|sqlserver|oracle|mariadb)://[^:]+:[^@]+@[^\s'"]+`,
			description: "Database Connection String with credentials detected",
			cwe:         "CWE-798", keywords: []string{"://"},
			remediation: "Use environment variables or a secrets manager for database connection strings.",
			references:  []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "SEC-074", severity: findings.SeverityCritical, confidence: findings.ConfidenceHigh,
			pattern:     `mongodb\+srv://[^:]+:[^@]+@[^\s'"]+`,
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
			pattern:     `rediss?://[^:]+:[^@]+@[^\s'"]+`,
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
			pattern:     `https?://[^:]+:[^@]+@[^\s'"]{3,}`,
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
	}

	out := make([]rules.Rule, 0, len(defs))
	for _, d := range defs {
		out = append(out, rules.Rule{
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
	return out
}
