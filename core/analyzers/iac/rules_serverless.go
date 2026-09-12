package iac

import (
	"github.com/nox-hq/nox/core/findings"
	"github.com/nox-hq/nox/core/rules"
)

// builtinServerlessRules returns built-in Serverless Framework security rules (IAC-246 to IAC-265).
func builtinServerlessRules() []rules.Rule {
	serverlessFilePatterns := []string{"serverless.yml", "serverless.yaml", "serverless.ts", "*.yml", "*.yaml"}

	defs := []iacRule{
		{
			id: "IAC-246", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:      `(?i)Action:\s*['"]?\*['"]?`,
			description:  "Serverless IAM wildcard action",
			cwe:          "CWE-250",
			keywords:     []string{"Action", "*"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "privilege"},
			remediation:  "Replace wildcard IAM actions with specific, least-privilege actions required by the function. Use fine-grained actions like 's3:GetObject' instead of 's3:*' or '*'.",
			references:   []string{"https://cwe.mitre.org/data/definitions/250.html"},
		},
		{
			id: "IAC-247", severity: findings.SeverityHigh, confidence: findings.ConfidenceMedium,
			pattern:      `(?i)Resource:\s*['"]?\*['"]?`,
			description:  "Serverless IAM wildcard resource",
			cwe:          "CWE-250",
			keywords:     []string{"Resource", "*"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "privilege"},
			remediation:  "Scope IAM resources to specific ARNs instead of '*'. Use variables like ${self:provider.environment.TABLE_ARN} to reference specific resources dynamically.",
			references:   []string{"https://cwe.mitre.org/data/definitions/250.html"},
		},
		{
			id: "IAC-248", severity: findings.SeverityMedium, confidence: findings.ConfidenceMedium,
			pattern:      `(?i)timeout:\s*(?:9[0-9][0-9]|[0-9]{4,})`,
			description:  "Serverless function with excessive timeout (>900s)",
			cwe:          "CWE-770",
			keywords:     []string{"timeout"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "resource-management"},
			remediation:  "Reduce function timeout to the minimum required for the operation. Excessive timeouts increase cost exposure and can mask performance issues. Most functions should complete within 30 seconds.",
			references:   []string{"https://cwe.mitre.org/data/definitions/770.html"},
		},
		{
			id: "IAC-249", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:      `(?i)memorySize:\s*(?:1[0-9]{4,}|[2-9][0-9]{4,})`,
			description:  "Serverless function with excessive memory (>10GB)",
			cwe:          "CWE-770",
			keywords:     []string{"memorySize"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "resource-management"},
			remediation:  "Right-size function memory allocation based on profiling data. Excessive memory increases cost and rarely improves performance. Use AWS Lambda Power Tuning to find optimal settings.",
			references:   []string{"https://cwe.mitre.org/data/definitions/770.html"},
		},
		{
			id: "IAC-250", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:      `(?i)-\s*http:\s*\n\s*path:`,
			description:  "Serverless HTTP endpoint (verify authorization)",
			cwe:          "CWE-284",
			keywords:     []string{"http", "events"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "network"},
			remediation:  "Add an authorizer to HTTP event endpoints. Use API Gateway authorizers (Cognito, Lambda, or IAM) to enforce authentication and prevent unauthorized access.",
			references:   []string{"https://cwe.mitre.org/data/definitions/284.html"},
		},
		{
			id: "IAC-251", severity: findings.SeverityMedium, confidence: findings.ConfidenceHigh,
			pattern:      `(?i)cors:\s*true`,
			description:  "Serverless enables CORS for all origins",
			cwe:          "CWE-346",
			keywords:     []string{"cors"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "network"},
			remediation:  "Configure CORS with specific allowed origins instead of allowing all. Use an object with 'origin' set to your domain(s) and restrict 'headers' and 'methods' to those required.",
			references:   []string{"https://cwe.mitre.org/data/definitions/346.html"},
		},
		{
			id: "IAC-252", severity: findings.SeverityMedium, confidence: findings.ConfidenceHigh,
			pattern:      `(?i)private:\s*false`,
			description:  "Serverless function explicitly set to public",
			cwe:          "CWE-284",
			keywords:     []string{"private"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "network"},
			remediation:  "Set 'private: true' and use API keys or authorizers to control access. Publicly accessible functions are exposed to the internet without any authentication.",
			references:   []string{"https://cwe.mitre.org/data/definitions/284.html"},
		},
		{
			id: "IAC-253", severity: findings.SeverityLow, confidence: findings.ConfidenceHigh,
			pattern:      `(?i)tracing:\s*(?:false|'false')`,
			description:  "Serverless disables X-Ray tracing",
			cwe:          "CWE-693",
			keywords:     []string{"tracing"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "logging"},
			remediation:  "Enable AWS X-Ray tracing (tracing: true) for observability into function execution, latency analysis, and error debugging in production environments.",
			references:   []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
		{
			id: "IAC-254", severity: findings.SeverityCritical, confidence: findings.ConfidenceMedium,
			pattern:      `(?i)(?:PASSWORD|SECRET_KEY|API_KEY|DB_PASSWORD)\s*:\s*['"]?[A-Za-z0-9]`,
			description:  "Serverless environment variable with hardcoded secret",
			cwe:          "CWE-798",
			keywords:     []string{"environment", "PASSWORD", "SECRET"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "secrets"},
			remediation:  "Use AWS SSM Parameter Store or Secrets Manager references (${ssm:/path/to/secret}) instead of hardcoded values. Hardcoded secrets in serverless.yml are exposed in version control and CloudFormation.",
			references:   []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "IAC-255", severity: findings.SeverityMedium, confidence: findings.ConfidenceHigh,
			pattern:      `(?i)reservedConcurrency:\s*0`,
			description:  "Serverless function with zero reserved concurrency (disabled)",
			cwe:          "CWE-693",
			keywords:     []string{"reservedConcurrency"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "availability"},
			remediation:  "Setting reservedConcurrency to 0 effectively disables the function. If this is intentional (e.g., maintenance mode), document it. Otherwise, set an appropriate concurrency limit.",
			references:   []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
		{
			id: "IAC-256", severity: findings.SeverityLow, confidence: findings.ConfidenceMedium,
			pattern:      `(?i)provisionedConcurrency:\s*(?:[5-9][0-9]|[0-9]{3,})`,
			description:  "Serverless high provisioned concurrency (cost risk)",
			cwe:          "CWE-770",
			keywords:     []string{"provisionedConcurrency"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "resource-management"},
			remediation:  "Review high provisioned concurrency settings for cost impact. Provisioned concurrency incurs charges even when idle. Use auto-scaling with Application Auto Scaling for dynamic workloads.",
			references:   []string{"https://cwe.mitre.org/data/definitions/770.html"},
		},
		{
			id: "IAC-257", severity: findings.SeverityHigh, confidence: findings.ConfidenceHigh,
			pattern:      `(?i)runtime:\s*['"]?(?:python2|nodejs[0-9]|ruby2\.5|dotnetcore2)`,
			description:  "Serverless uses deprecated runtime",
			cwe:          "CWE-672",
			keywords:     []string{"runtime", "deprecated"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "supply-chain"},
			remediation:  "Upgrade to a supported runtime version. Deprecated runtimes no longer receive security patches and may be forcibly disabled by AWS. Migrate to the latest LTS version of your runtime.",
			references:   []string{"https://cwe.mitre.org/data/definitions/672.html"},
		},
		{
			id: "IAC-258", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			pattern:      `(?i)layers:\s*\n\s*-\s*arn:aws:lambda:.*:layer:`,
			description:  "Serverless references external Lambda layer (verify trust)",
			cwe:          "CWE-829",
			keywords:     []string{"layers", "arn"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "supply-chain"},
			remediation:  "Verify the trust and integrity of external Lambda layers. Prefer layers from your own account or trusted publishers. Pin layer versions explicitly and audit layer contents periodically.",
			references:   []string{"https://cwe.mitre.org/data/definitions/829.html"},
		},
		{
			id: "IAC-259", severity: findings.SeverityLow, confidence: findings.ConfidenceLow,
			pattern:      `(?i)plugins:\s*\n\s*-\s*serverless-`,
			description:  "Serverless plugin dependency (verify security)",
			cwe:          "CWE-829",
			keywords:     []string{"plugins", "serverless"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "supply-chain"},
			remediation:  "Audit Serverless Framework plugins for security and maintenance status. Pin plugin versions in package.json and review plugin source code, especially for plugins with deployment hooks.",
			references:   []string{"https://cwe.mitre.org/data/definitions/829.html"},
		},
		{
			id: "IAC-260", severity: findings.SeverityLow, confidence: findings.ConfidenceLow,
			// (?m): without it this matched only at end of file. The anchor is
			// the point of the rule — `apiKeys:` with nothing after it on the
			// line is the block opener — so it needs the flag to mean that.
			pattern:      `(?im)apiKeys:\s*$`,
			description:  "Serverless API keys configured (verify rotation)",
			cwe:          "CWE-798",
			keywords:     []string{"apiKeys"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "secrets"},
			remediation:  "Implement API key rotation policies. Use usage plans with throttling and quota limits. Consider replacing API keys with IAM or Cognito authorizers for stronger authentication.",
			references:   []string{"https://cwe.mitre.org/data/definitions/798.html"},
		},
		{
			id: "IAC-261", severity: findings.SeverityLow, confidence: findings.ConfidenceLow,
			// (?m): without it this matched only at end of file.
			//
			// The description used to read "function without dead letter
			// queue", which is the opposite of what the pattern finds: an
			// `onError:` key with no value is a DLQ target DECLARED and left
			// empty. Restoring the anchor made the mismatch visible, so the
			// description now says what the rule detects. Absence of a DLQ
			// needs a block-scoped absence matcher, not this.
			pattern:      `(?im)onError:\s*$`,
			description:  "Serverless dead letter target declared with no value",
			cwe:          "CWE-693",
			keywords:     []string{"deadLetter", "onError"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "availability"},
			remediation:  "Configure a dead letter queue (SQS or SNS) using 'onError' or 'destinations' for async invocations. Without a DLQ, failed events are silently discarded after retry exhaustion.",
			references:   []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
		{
			id: "IAC-262", severity: findings.SeverityMedium, confidence: findings.ConfidenceLow,
			// (?m): without it this matched only at end of file.
			pattern:      `(?im)kmsKeyArn:\s*$`,
			description:  "Serverless empty KMS key ARN (no encryption)",
			cwe:          "CWE-311",
			keywords:     []string{"kmsKeyArn"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "encryption"},
			remediation:  "Provide a valid KMS key ARN for environment variable encryption at rest. Without a customer-managed KMS key, variables are encrypted with the default AWS Lambda service key.",
			references:   []string{"https://cwe.mitre.org/data/definitions/311.html"},
		},
		{
			id: "IAC-263", severity: findings.SeverityLow, confidence: findings.ConfidenceMedium,
			pattern:      `(?i)stage:\s*['"]?prod`,
			description:  "Serverless hardcoded production stage",
			cwe:          "CWE-693",
			keywords:     []string{"stage", "prod"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "best-practice"},
			remediation:  "Use a variable for the stage name (e.g., ${opt:stage, 'dev'}) instead of hardcoding 'prod'. Hardcoded stages prevent safe multi-environment deployment workflows.",
			references:   []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
		{
			id: "IAC-264", severity: findings.SeverityLow, confidence: findings.ConfidenceLow,
			pattern:      `(?i)endpointType:\s*['"]?EDGE['"]?`,
			description:  "Serverless uses EDGE endpoint (consider REGIONAL)",
			cwe:          "CWE-693",
			keywords:     []string{"endpointType", "EDGE"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "best-practice"},
			remediation:  "Consider using REGIONAL endpoints instead of EDGE for APIs consumed within the same region. REGIONAL endpoints have lower latency for same-region clients and support custom domain names with ACM certificates in the same region.",
			references:   []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
		{
			id: "IAC-265", severity: findings.SeverityLow, confidence: findings.ConfidenceLow,
			pattern:      `(?i)package:\s*\n\s*individually:\s*false`,
			description:  "Serverless packages all functions together",
			cwe:          "CWE-693",
			keywords:     []string{"package", "individually"},
			filePatterns: serverlessFilePatterns,
			tags:         []string{"iac", "serverless", "best-practice"},
			remediation:  "Set 'individually: true' under package to create separate deployment artifacts per function. This reduces cold start times, attack surface, and deployment size for each function.",
			references:   []string{"https://cwe.mitre.org/data/definitions/693.html"},
		},
	}

	// toRule, not a copy of it. Each of these three families carried its own
	// inline conversion that set MatcherType to "regex" unconditionally and
	// never read absenceAnchor, extraMetadata or retires — so a rule in one of
	// them declaring any of those loaded with the field silently discarded, and
	// an absence rule would have loaded with an empty pattern and matched
	// nothing. That is the failure this repository keeps meeting: a rule that
	// loads, lists, and finds nothing looks exactly like a rule that ran.
	out := make([]rules.Rule, len(defs))
	for i := range defs {
		out[i] = defs[i].toRule()
	}
	return out
}
