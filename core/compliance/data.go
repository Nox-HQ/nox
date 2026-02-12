package compliance

// complianceData returns the embedded compliance mapping data for all rules.
// Each rule is mapped to its applicable CIS, PCI-DSS, SOC2, NIST-800-53,
// HIPAA, OWASP Top 10, OWASP LLM Top 10, and OWASP Agentic controls.
func complianceData() map[string][]FrameworkControl {
	return map[string][]FrameworkControl{

		// =================================================================
		// Secret Detection Rules (SEC-*)
		// =================================================================

		// --- SEC-001 through SEC-015: Cloud Provider Secrets ---
		"SEC-001": { // AWS Access Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-002": { // AWS Secret Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-003": { // GitHub Token
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-004": { // Private Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-005": { // Generic High-Entropy Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-006": { // GCP API Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-007": { // Azure Subscription Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-008": { // DigitalOcean Token
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-009": { // Heroku API Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-010": { // Alibaba Cloud Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-011": { // IBM Cloud Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-012": { // Oracle Cloud Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-013": { // Linode Token
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-014": { // Vultr API Key
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-015": { // Cloudflare API Token
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- SEC-016 through SEC-022: GitHub/Git Tokens ---
		"SEC-016": { // GitHub Personal Access Token (classic)
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-017": { // GitHub Fine-Grained PAT
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-018": { // GitHub OAuth Token
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-019": { // GitHub App Token
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-020": { // GitLab Token
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-021": { // Bitbucket Token
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-022": { // Azure DevOps Token
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-023 through SEC-029: Payment/Communication Secrets ---
		"SEC-023": { // Stripe Secret Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-024": { // Stripe Restricted Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-025": { // PayPal Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-026": { // Square Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-027": { // Twilio API Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-028": { // SendGrid API Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-029": { // Mailgun API Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- SEC-030 through SEC-038: Crypto/PKI Secrets ---
		"SEC-030": { // JWT Secret
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-031": { // HMAC Secret
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-032": { // Encryption Key Material
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-033": { // SSL/TLS Certificate Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-034": { // PGP Private Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-035": { // SSH Private Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-036": { // PKCS12/PFX File
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-037": { // X.509 Private Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-038": { // Keystore Password
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- SEC-039 through SEC-044: Database Secrets ---
		"SEC-039": { // MySQL Connection String
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-040": { // PostgreSQL Connection String
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-041": { // MongoDB Connection String
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-042": { // Redis Connection String
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-043": { // Elasticsearch Credentials
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-044": { // Cassandra Credentials
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- SEC-045 through SEC-049: Container Registry Secrets ---
		"SEC-045": { // Docker Hub Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-046": { // AWS ECR Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-047": { // GCR Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-048": { // Azure ACR Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-049": { // GitHub Container Registry Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-050: Generic API Key ---
		"SEC-050": { // Generic API Key
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
		},

		// --- SEC-051 through SEC-056: CI/CD Secrets ---
		"SEC-051": { // Jenkins API Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-052": { // CircleCI Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-053": { // Travis CI Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-054": { // GitLab CI Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-055": { // Drone CI Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-056": { // TeamCity Token
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-057 through SEC-072: SaaS Secrets ---
		"SEC-057": { // Slack Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-058": { // Slack Webhook URL
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-059": { // Datadog API Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-060": { // New Relic Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-061": { // PagerDuty Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-062": { // Sentry DSN
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-063": { // Jira/Atlassian Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-064": { // Confluence Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-065": { // Zendesk Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-066": { // Shopify Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-067": { // Okta Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-068": { // Auth0 Secret
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-069": { // Firebase Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-070": { // Supabase Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-071": { // Vercel Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-072": { // Netlify Token
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- SEC-073 through SEC-076: Cloud Secret Manager Secrets ---
		"SEC-073": { // AWS Secrets Manager ARN
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-074": { // GCP Secret Manager Reference
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-075": { // Azure Key Vault Reference
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-076": { // HashiCorp Vault Token
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-077 through SEC-079: Private Keys/Certificates ---
		"SEC-077": { // PKCS8 Private Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-078": { // EC Private Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-079": { // DSA Private Key
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- SEC-080 through SEC-086: Generic Patterns ---
		"SEC-080": { // Generic Password in Config
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
		},
		"SEC-081": { // Generic Token Pattern
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-082": { // Generic Secret in URL
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
		},
		"SEC-083": { // Base64 Encoded Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-084": { // Hex Encoded Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-085": { // Hardcoded Credential
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
		},
		"SEC-086": { // Environment Variable Leak
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// =================================================================
		// IaC Rules (IAC-*)
		// =================================================================

		// --- IAC-001 through IAC-003: Docker Core Rules ---
		"IAC-001": { // Dockerfile root user
			{CIS, "CIS 4.1", "Ensure a user for the container has been created"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-002": { // Unpinned base image
			{CIS, "CIS 4.7", "Ensure update instructions are not used alone"},
			{PCIDSS, "PCI-DSS 6.3.2", "Secure development lifecycle"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-003": { // COPY --chown missing
			{CIS, "CIS 4.1", "Ensure a user for the container has been created"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},

		// --- IAC-004 through IAC-006: Terraform Network Rules ---
		"IAC-004": { // Public CIDR 0.0.0.0/0
			{CIS, "CIS 5.2", "Ensure no security groups allow ingress from 0.0.0.0/0"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-005": { // Encryption disabled
			{CIS, "CIS 2.1.1", "Ensure S3 bucket encryption is enabled"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-006": { // SSH port 22
			{CIS, "CIS 5.2", "Ensure no security groups allow ingress to SSH"},
			{PCIDSS, "PCI-DSS 1.3.4", "Do not allow unauthorized outbound traffic"},
			{NIST80053, "NIST AC-17", "Remote access"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},

		// --- IAC-007 through IAC-010: Kubernetes Privilege Rules ---
		"IAC-007": { // K8s privileged pod
			{CIS, "CIS 5.2.1", "Minimize admission of privileged containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-008": { // K8s host network
			{CIS, "CIS 5.2.4", "Minimize admission of containers with hostNetwork"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-009": { // K8s privilege escalation
			{CIS, "CIS 5.2.5", "Minimize admission with allowPrivilegeEscalation"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-010": { // K8s root user
			{CIS, "CIS 5.2.6", "Minimize admission of root containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},

		// --- IAC-011 through IAC-018: GitHub Actions Rules ---
		"IAC-011": { // GHA pull_request_target
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
		},
		"IAC-012": { // GHA script injection
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},
		"IAC-013": { // GHA unpinned action
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-014": { // GHA write-all permissions
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-015": { // GHA secrets in plaintext
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
		},
		"IAC-016": { // GHA artifact poisoning
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-017": { // GHA self-hosted runner risk
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
		},
		"IAC-018": { // GHA debug logging enabled
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},

		// --- IAC-019 through IAC-021: Docker Compose Rules ---
		"IAC-019": { // Compose privileged
			{CIS, "CIS 5.2.1", "Minimize admission of privileged containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-020": { // Compose host network
			{CIS, "CIS 5.2.4", "Minimize admission of containers with hostNetwork"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-021": { // Docker socket mount
			{CIS, "CIS 5.31", "Ensure Docker socket is not mounted inside containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},

		// --- IAC-022 through IAC-025: Docker Additional Rules ---
		"IAC-022": { // ADD instead of COPY
			{CIS, "CIS 4.9", "Ensure COPY is used instead of ADD"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-023": { // HEALTHCHECK missing
			{CIS, "CIS 4.6", "Ensure HEALTHCHECK instructions have been added"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-024": { // Secrets in ENV
			{CIS, "CIS 4.10", "Ensure secrets are not stored in Dockerfiles"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-025": { // Latest tag used
			{CIS, "CIS 4.7", "Ensure update instructions are not used alone"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},

		// --- IAC-026 through IAC-035: Kubernetes Additional Rules ---
		"IAC-026": { // K8s hostPath mount
			{CIS, "CIS 5.2.3", "Minimize admission of containers with hostPath"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-027": { // K8s hostPID
			{CIS, "CIS 5.2.2", "Minimize admission of containers with hostPID"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-028": { // K8s hostIPC
			{CIS, "CIS 5.2.3", "Minimize admission of containers sharing host IPC"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-029": { // K8s capabilities not dropped
			{CIS, "CIS 5.2.7", "Minimize admission of containers with added capabilities"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-030": { // K8s resource limits missing
			{CIS, "CIS 5.4.1", "Ensure resource limits are set on containers"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-031": { // K8s default namespace
			{CIS, "CIS 5.7.1", "Ensure the default namespace is not actively used"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-032": { // K8s readOnlyRootFilesystem
			{CIS, "CIS 5.2.8", "Minimize admission of containers with readOnlyRootFilesystem"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-033": { // K8s service account token auto-mount
			{CIS, "CIS 5.1.6", "Ensure automounting service account tokens is disabled"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-034": { // K8s image pull policy
			{CIS, "CIS 5.5.1", "Ensure image pull policy is Always"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-035": { // K8s secrets in env
			{CIS, "CIS 5.4.2", "Ensure secrets are not stored in environment variables"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- IAC-036 through IAC-042: Terraform Network/Encryption ---
		"IAC-036": { // RDS publicly accessible
			{CIS, "CIS 2.3.2", "Ensure RDS instances are not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-037": { // RDS encryption disabled
			{CIS, "CIS 2.3.1", "Ensure RDS encryption is enabled"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
		},
		"IAC-038": { // CloudTrail multi-region
			{CIS, "CIS 3.1", "Ensure CloudTrail is enabled in all regions"},
			{PCIDSS, "PCI-DSS 10.1", "Implement audit trails"},
			{NIST80053, "NIST AU-2", "Audit events"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
			{HIPAA, "HIPAA 164.312(b)", "Audit controls"},
		},
		"IAC-039": { // IAM wildcard
			{CIS, "CIS 1.16", "Ensure IAM policies do not allow full * admin privileges"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-040": { // S3 public ACL
			{CIS, "CIS 2.1.5", "Ensure S3 buckets deny public access"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-041": { // HTTP listener
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{HIPAA, "HIPAA 164.312(e)(1)", "Transmission security"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-042": { // Azure HTTP allowed
			{CIS, "CIS 3.1", "Ensure secure transfer required is enabled"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{HIPAA, "HIPAA 164.312(e)(1)", "Transmission security"},
		},

		// --- IAC-043 through IAC-045: Terraform Encryption Rules ---
		"IAC-043": { // EBS encryption disabled
			{CIS, "CIS 2.2.1", "Ensure EBS volume encryption is enabled"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
		},
		"IAC-044": { // CloudWatch log encryption
			{CIS, "CIS 3.9", "Ensure CloudWatch log groups are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{NIST80053, "NIST AU-2", "Audit events"},
			{HIPAA, "HIPAA 164.312(b)", "Audit controls"},
		},
		"IAC-045": { // SNS topic encryption
			{CIS, "CIS 2.1.1", "Ensure encryption is enabled for SNS topics"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
		},

		// --- IAC-046 through IAC-050: Terraform Network Rules ---
		"IAC-046": { // ElastiCache publicly accessible
			{CIS, "CIS 5.2", "Ensure no public access to cache clusters"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-047": { // Elasticsearch public access
			{CIS, "CIS 5.2", "Ensure Elasticsearch domains are not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-048": { // Redshift publicly accessible
			{CIS, "CIS 5.2", "Ensure Redshift clusters are not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-049": { // Lambda public access
			{CIS, "CIS 5.2", "Ensure Lambda functions are not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-050": { // API Gateway without authorization
			{CIS, "CIS 5.2", "Ensure API Gateway has proper authorization"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},

		// --- IAC-051 through IAC-060: Terraform IAM/Privilege Rules ---
		"IAC-051": { // IAM user with console access and no MFA
			{CIS, "CIS 1.2", "Ensure MFA is enabled for all IAM users with console access"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-052": { // IAM policy allows AssumeRole wildcard
			{CIS, "CIS 1.16", "Ensure IAM policies are attached only to groups or roles"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-053": { // Root account access key
			{CIS, "CIS 1.12", "Ensure no root account access key exists"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-054": { // IAM password policy too weak
			{CIS, "CIS 1.8", "Ensure IAM password policy requires minimum length"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-055": { // IAM role without boundary
			{CIS, "CIS 1.16", "Ensure IAM policies do not allow full * admin privileges"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-056": { // Cross-account trust too broad
			{CIS, "CIS 1.16", "Ensure IAM trust policies are scoped"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-057": { // S3 bucket policy allows public read
			{CIS, "CIS 2.1.5", "Ensure S3 buckets deny public access"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-058": { // SQS queue policy too permissive
			{CIS, "CIS 1.16", "Ensure SQS policies restrict public access"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-059": { // KMS key policy allows wildcard
			{CIS, "CIS 1.16", "Ensure KMS key policies restrict access"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-060": { // Lambda execution role too broad
			{CIS, "CIS 1.16", "Ensure Lambda roles follow least privilege"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},

		// --- IAC-061 through IAC-080: Terraform Supply Chain Rules ---
		"IAC-061": { // Unpinned Terraform provider
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.3.2", "Secure development lifecycle"},
		},
		"IAC-062": { // Unpinned Terraform module
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{PCIDSS, "PCI-DSS 6.3.2", "Secure development lifecycle"},
		},
		"IAC-063": { // Module from untrusted registry
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-064": { // Remote exec provisioner
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-065": { // Local exec provisioner
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-066": { // External data source
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-067": { // HTTP data source without TLS
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
		},
		"IAC-068": { // Backend without encryption
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-069": { // Backend without state locking
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-070": { // S3 backend without versioning
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-071": { // Terraform state contains secrets
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
		},
		"IAC-072": { // Provider version constraint too loose
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-073": { // Module source uses branch ref
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-074": { // No required_providers block
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-075": { // Terraform version unconstrained
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-076": { // Remote state data source
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
		},
		"IAC-077": { // Null resource with triggers
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-078": { // Cloud-init with inline scripts
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-079": { // User data script in plaintext
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
		},
		"IAC-080": { // Module output exposes sensitive data
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- IAC-081 through IAC-105: Terraform Miscellaneous Rules ---
		"IAC-081": { // VPC flow logs disabled
			{CIS, "CIS 3.9", "Ensure VPC flow logging is enabled"},
			{NIST80053, "NIST AU-2", "Audit events"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-082": { // Default VPC in use
			{CIS, "CIS 4.3", "Ensure the default VPC is not used"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-083": { // Security group allows all egress
			{CIS, "CIS 5.4", "Ensure default security group restricts all traffic"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-084": { // ELB access logging disabled
			{CIS, "CIS 3.1", "Ensure ELB access logging is enabled"},
			{PCIDSS, "PCI-DSS 10.1", "Implement audit trails"},
			{NIST80053, "NIST AU-2", "Audit events"},
		},
		"IAC-085": { // GuardDuty not enabled
			{CIS, "CIS 4.15", "Ensure GuardDuty is enabled"},
			{NIST80053, "NIST SI-4", "Information system monitoring"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-086": { // Config service not enabled
			{CIS, "CIS 3.5", "Ensure AWS Config is enabled in all regions"},
			{NIST80053, "NIST CM-8", "Information system component inventory"},
			{SOC2, "SOC2 CC7.1", "Detect and monitor changes"},
		},
		"IAC-087": { // S3 versioning disabled
			{CIS, "CIS 2.1.3", "Ensure S3 bucket versioning is enabled"},
			{NIST80053, "NIST CP-9", "Information system backup"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-088": { // S3 access logging disabled
			{CIS, "CIS 2.1.1", "Ensure S3 bucket access logging is enabled"},
			{PCIDSS, "PCI-DSS 10.1", "Implement audit trails"},
			{NIST80053, "NIST AU-2", "Audit events"},
		},
		"IAC-089": { // DynamoDB encryption disabled
			{CIS, "CIS 2.4", "Ensure DynamoDB tables are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-090": { // DynamoDB PITR disabled
			{NIST80053, "NIST CP-9", "Information system backup"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-091": { // ECR image scanning disabled
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
			{PCIDSS, "PCI-DSS 6.2", "Ensure all systems are protected from known vulnerabilities"},
		},
		"IAC-092": { // ECR immutable tags disabled
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-093": { // ECS task definition with host network
			{CIS, "CIS 5.2.4", "Minimize use of host networking"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-094": { // ECS task privileged
			{CIS, "CIS 5.2.1", "Minimize admission of privileged containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-095": { // CloudFront without WAF
			{NIST80053, "NIST SC-7", "Boundary protection"},
			{PCIDSS, "PCI-DSS 6.6", "Address new threats and vulnerabilities"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-096": { // CloudFront minimum TLS version
			{CIS, "CIS 2.1.2", "Ensure minimum TLS version for CloudFront"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
		},
		"IAC-097": { // SQS encryption disabled
			{CIS, "CIS 2.1.1", "Ensure SQS queues are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-098": { // Kinesis encryption disabled
			{CIS, "CIS 2.1.1", "Ensure Kinesis streams are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-099": { // Neptune cluster not encrypted
			{CIS, "CIS 2.4", "Ensure Neptune clusters are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-100": { // DocumentDB not encrypted
			{CIS, "CIS 2.4", "Ensure DocumentDB clusters are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-101": { // Secrets Manager rotation disabled
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-102": { // SSM parameter not encrypted
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
		},
		"IAC-103": { // WAF rule group empty
			{NIST80053, "NIST SC-7", "Boundary protection"},
			{PCIDSS, "PCI-DSS 6.6", "Address new threats and vulnerabilities"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-104": { // Route53 DNSSEC disabled
			{NIST80053, "NIST SC-20", "Secure name/address resolution service"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-105": { // ACM certificate expiry not monitored
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},

		// --- IAC-106 through IAC-130: Helm Chart Rules ---
		"IAC-106": { // Helm privileged container
			{CIS, "CIS 5.2.1", "Minimize admission of privileged containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-107": { // Helm root user
			{CIS, "CIS 5.2.6", "Minimize admission of root containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-108": { // Helm privilege escalation
			{CIS, "CIS 5.2.5", "Minimize admission with allowPrivilegeEscalation"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-109": { // Helm hostNetwork
			{CIS, "CIS 5.2.4", "Minimize admission of containers with hostNetwork"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-110": { // Helm hostPID
			{CIS, "CIS 5.2.2", "Minimize admission of containers with hostPID"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-111": { // Helm hostIPC
			{CIS, "CIS 5.2.3", "Minimize admission of containers sharing host IPC"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-112": { // Helm hostPath mount
			{CIS, "CIS 5.2.3", "Minimize admission of containers with hostPath"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-113": { // Helm capabilities not dropped
			{CIS, "CIS 5.2.7", "Minimize admission of containers with added capabilities"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-114": { // Helm resource limits missing
			{CIS, "CIS 5.4.1", "Ensure resource limits are set on containers"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-115": { // Helm readOnlyRootFilesystem
			{CIS, "CIS 5.2.8", "Minimize containers without readOnlyRootFilesystem"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-116": { // Helm service account auto-mount
			{CIS, "CIS 5.1.6", "Ensure automounting service account tokens is disabled"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-117": { // Helm default namespace
			{CIS, "CIS 5.7.1", "Ensure the default namespace is not actively used"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-118": { // Helm unpinned image tag
			{CIS, "CIS 5.5.1", "Ensure container images use fixed tags"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-119": { // Helm secrets in values
			{CIS, "CIS 5.4.2", "Ensure secrets are not in Helm values"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-120": { // Helm Tiller enabled
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-121": { // Helm chart from untrusted repo
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-122": { // Helm network policy missing
			{CIS, "CIS 5.3.2", "Ensure NetworkPolicy is configured"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-123": { // Helm pod security policy missing
			{CIS, "CIS 5.2.1", "Ensure PodSecurityPolicy is configured"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-124": { // Helm RBAC not configured
			{CIS, "CIS 5.1.1", "Ensure RBAC is properly configured"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-125": { // Helm cluster-admin binding
			{CIS, "CIS 5.1.1", "Minimize use of cluster-admin role binding"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-126": { // Helm liveness probe missing
			{CIS, "CIS 5.4.1", "Ensure liveness probes are configured"},
			{NIST80053, "NIST SI-6", "Security function verification"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-127": { // Helm readiness probe missing
			{CIS, "CIS 5.4.1", "Ensure readiness probes are configured"},
			{NIST80053, "NIST SI-6", "Security function verification"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-128": { // Helm ingress without TLS
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-129": { // Helm image pull secrets missing
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{CIS, "CIS 5.5.1", "Ensure image pull secrets are configured"},
		},
		"IAC-130": { // Helm seccomp profile missing
			{CIS, "CIS 5.2.9", "Ensure seccomp profile is set"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},

		// --- IAC-131 through IAC-150: CloudFormation Rules ---
		"IAC-131": { // CFN S3 bucket not encrypted
			{CIS, "CIS 2.1.1", "Ensure S3 bucket encryption is enabled"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-132": { // CFN S3 bucket public access
			{CIS, "CIS 2.1.5", "Ensure S3 buckets deny public access"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
		},
		"IAC-133": { // CFN RDS not encrypted
			{CIS, "CIS 2.3.1", "Ensure RDS encryption is enabled"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-134": { // CFN RDS publicly accessible
			{CIS, "CIS 2.3.2", "Ensure RDS instances are not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-135": { // CFN security group open ingress
			{CIS, "CIS 5.2", "Ensure no security groups allow ingress from 0.0.0.0/0"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-136": { // CFN IAM wildcard permissions
			{CIS, "CIS 1.16", "Ensure IAM policies do not allow full * admin privileges"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-137": { // CFN EBS not encrypted
			{CIS, "CIS 2.2.1", "Ensure EBS volume encryption is enabled"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-138": { // CFN CloudTrail not enabled
			{CIS, "CIS 3.1", "Ensure CloudTrail is enabled in all regions"},
			{PCIDSS, "PCI-DSS 10.1", "Implement audit trails"},
			{NIST80053, "NIST AU-2", "Audit events"},
		},
		"IAC-139": { // CFN Lambda without VPC
			{CIS, "CIS 5.2", "Ensure Lambda functions are in a VPC"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-140": { // CFN ELB without HTTPS
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{HIPAA, "HIPAA 164.312(e)(1)", "Transmission security"},
		},
		"IAC-141": { // CFN DynamoDB not encrypted
			{CIS, "CIS 2.4", "Ensure DynamoDB tables are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-142": { // CFN SNS topic not encrypted
			{CIS, "CIS 2.1.1", "Ensure encryption is enabled for SNS topics"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-143": { // CFN SQS queue not encrypted
			{CIS, "CIS 2.1.1", "Ensure SQS queues are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-144": { // CFN Kinesis not encrypted
			{CIS, "CIS 2.1.1", "Ensure Kinesis streams are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-145": { // CFN CloudFront without HTTPS
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-146": { // CFN API Gateway without auth
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"IAC-147": { // CFN WAF not configured
			{NIST80053, "NIST SC-7", "Boundary protection"},
			{PCIDSS, "PCI-DSS 6.6", "Address new threats and vulnerabilities"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-148": { // CFN VPC flow logs disabled
			{CIS, "CIS 3.9", "Ensure VPC flow logging is enabled"},
			{NIST80053, "NIST AU-2", "Audit events"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-149": { // CFN GuardDuty not enabled
			{CIS, "CIS 4.15", "Ensure GuardDuty is enabled"},
			{NIST80053, "NIST SI-4", "Information system monitoring"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-150": { // CFN secrets in template parameters
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- IAC-151 through IAC-160: Pulumi Rules ---
		"IAC-151": { // Pulumi S3 bucket not encrypted
			{CIS, "CIS 2.1.1", "Ensure S3 bucket encryption is enabled"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
		},
		"IAC-152": { // Pulumi security group open ingress
			{CIS, "CIS 5.2", "Ensure no security groups allow ingress from 0.0.0.0/0"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
		},
		"IAC-153": { // Pulumi RDS not encrypted
			{CIS, "CIS 2.3.1", "Ensure RDS encryption is enabled"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable"},
		},
		"IAC-154": { // Pulumi IAM wildcard
			{CIS, "CIS 1.16", "Ensure IAM policies do not allow full * admin privileges"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
		},
		"IAC-155": { // Pulumi EBS not encrypted
			{CIS, "CIS 2.2.1", "Ensure EBS volume encryption is enabled"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
		},
		"IAC-156": { // Pulumi Lambda without VPC
			{CIS, "CIS 5.2", "Ensure Lambda functions are in a VPC"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-157": { // Pulumi CloudTrail disabled
			{CIS, "CIS 3.1", "Ensure CloudTrail is enabled in all regions"},
			{NIST80053, "NIST AU-2", "Audit events"},
			{PCIDSS, "PCI-DSS 10.1", "Implement audit trails"},
		},
		"IAC-158": { // Pulumi ELB without HTTPS
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{HIPAA, "HIPAA 164.312(e)(1)", "Transmission security"},
		},
		"IAC-159": { // Pulumi secrets in config
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-160": { // Pulumi hardcoded credentials
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- IAC-161 through IAC-175: Docker Additional Rules ---
		"IAC-161": { // Dockerfile EXPOSE all ports
			{CIS, "CIS 4.5", "Ensure only necessary ports are exposed"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-162": { // Dockerfile sudo installed
			{CIS, "CIS 4.1", "Ensure sudo is not installed in container"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-163": { // Dockerfile curl/wget pipe to shell
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{CIS, "CIS 4.7", "Ensure untrusted scripts are not piped to shell"},
		},
		"IAC-164": { // Dockerfile apt-get without --no-install-recommends
			{CIS, "CIS 4.3", "Ensure unnecessary packages are not installed"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{NIST80053, "NIST CM-7", "Least functionality"},
		},
		"IAC-165": { // Dockerfile missing WORKDIR
			{CIS, "CIS 4.8", "Ensure WORKDIR is specified"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-166": { // Dockerfile MAINTAINER deprecated
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{CIS, "CIS 4.8", "Use LABEL instead of MAINTAINER"},
		},
		"IAC-167": { // Dockerfile multiple ENTRYPOINT
			{CIS, "CIS 4.8", "Ensure only one ENTRYPOINT is defined"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
		},
		"IAC-168": { // Dockerfile cache mount secrets
			{CIS, "CIS 4.10", "Ensure secrets are not stored in build cache"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-169": { // Dockerfile .dockerignore missing
			{CIS, "CIS 4.10", "Ensure .dockerignore is configured"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-170": { // Dockerfile setuid/setgid binaries
			{CIS, "CIS 4.1", "Remove setuid/setgid binaries from container"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-171": { // Dockerfile GPG key validation missing
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-172": { // Dockerfile RUN with --privileged
			{CIS, "CIS 4.1", "Ensure privileged builds are not used"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-173": { // Dockerfile package manager cache not cleaned
			{CIS, "CIS 4.3", "Ensure package manager cache is cleaned"},
			{NIST80053, "NIST CM-7", "Least functionality"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
		},
		"IAC-174": { // Dockerfile multiple FROM without multi-stage
			{CIS, "CIS 4.7", "Use multi-stage builds to minimize image size"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-175": { // Dockerfile hardcoded apt sources
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{CIS, "CIS 4.7", "Ensure package sources are trusted"},
		},

		// --- IAC-176 through IAC-185: Helm/Compose Additional Rules ---
		"IAC-176": { // Helm AppArmor profile missing
			{CIS, "CIS 5.2.9", "Ensure AppArmor profile is set"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-177": { // Helm pod disruption budget missing
			{CIS, "CIS 5.4.1", "Ensure PodDisruptionBudget is configured"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
		},
		"IAC-178": { // Helm anti-affinity rules missing
			{CIS, "CIS 5.4.1", "Ensure pod anti-affinity is configured"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
		},
		"IAC-179": { // Compose environment file secrets
			{CIS, "CIS 5.4.2", "Ensure secrets are not in environment files"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-180": { // Compose host port binding
			{CIS, "CIS 5.13", "Ensure host port bindings are restricted"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-181": { // Compose cap_add without cap_drop
			{CIS, "CIS 5.2.7", "Minimize capabilities added to containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-182": { // Compose restart policy missing
			{CIS, "CIS 5.14", "Ensure restart policy is configured"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
		},
		"IAC-183": { // Compose PID mode host
			{CIS, "CIS 5.2.2", "Minimize containers sharing host PID"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-184": { // Docker LABEL schema missing
			{CIS, "CIS 4.8", "Ensure container images have proper labels"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
		},
		"IAC-185": { // Compose logging driver missing
			{CIS, "CIS 5.12", "Ensure logging is configured for containers"},
			{NIST80053, "NIST AU-2", "Audit events"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},

		// =================================================================
		// Vulnerability Rules (VULN-*)
		// =================================================================
		"VULN-001": { // Known vulnerability
			{PCIDSS, "PCI-DSS 6.2", "Ensure all systems are protected from known vulnerabilities"},
			{NIST80053, "NIST SI-2", "Flaw remediation"},
			{SOC2, "SOC2 CC7.1", "Detect and monitor changes"},
			{HIPAA, "HIPAA 164.308(a)(5)(ii)(B)", "Protection from malicious software"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"VULN-002": { // Typosquatting
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"VULN-003": { // Malicious package
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},

		// =================================================================
		// Container Rules (CONT-*)
		// =================================================================
		"CONT-001": { // Unpinned container image
			{CIS, "CIS 4.7", "Ensure update instructions are not used alone"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"CONT-002": { // Outdated base image
			{CIS, "CIS 4.7", "Ensure update instructions are not used alone"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},

		// =================================================================
		// License Rules (LIC-*)
		// =================================================================
		"LIC-001": { // Copyleft or restricted license
			{SOC2, "SOC2 CC9.2", "Risk assessment and management"},
		},

		// =================================================================
		// AI Security Rules (AI-*)
		// =================================================================

		// --- Prompt Injection / Input Validation ---
		"AI-001": { // System prompt injection risk
			{OWASPLLM, "LLM01", "Prompt Injection"},
			{OWASPAgent, "AG03", "Tool Injection"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},
		"AI-002": { // User prompt not sanitized
			{OWASPLLM, "LLM01", "Prompt Injection"},
			{OWASPAgent, "AG03", "Tool Injection"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},
		"AI-003": { // RAG boundary violation
			{OWASPLLM, "LLM01", "Prompt Injection"},
			{OWASPAgent, "AG03", "Tool Injection"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},
		"AI-010": { // Indirect prompt injection via context
			{OWASPLLM, "LLM01", "Prompt Injection"},
			{OWASPAgent, "AG03", "Tool Injection"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},

		// --- Insecure Output Handling ---
		"AI-009": { // Unvalidated LLM output rendered
			{OWASPLLM, "LLM02", "Insecure Output Handling"},
			{OWASPAgent, "AG06", "Output Misuse"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},
		"AI-012": { // LLM output used in code execution
			{OWASPLLM, "LLM02", "Insecure Output Handling"},
			{OWASPAgent, "AG06", "Output Misuse"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},
		"AI-015": { // LLM output used in SQL query
			{OWASPLLM, "LLM02", "Insecure Output Handling"},
			{OWASPAgent, "AG06", "Output Misuse"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},
		"AI-018": { // LLM output used in system command
			{OWASPLLM, "LLM02", "Insecure Output Handling"},
			{OWASPAgent, "AG06", "Output Misuse"},
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
		},

		// --- Excessive Agency / Tool Permissions ---
		"AI-004": { // Unsafe tool exposure
			{OWASPLLM, "LLM08", "Excessive Agency"},
			{OWASPAgent, "AG01", "Excessive Tool Permissions"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"AI-005": { // MCP tool without access control
			{OWASPLLM, "LLM08", "Excessive Agency"},
			{OWASPAgent, "AG01", "Excessive Tool Permissions"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"AI-011": { // Agent with unrestricted filesystem access
			{OWASPLLM, "LLM08", "Excessive Agency"},
			{OWASPAgent, "AG01", "Excessive Tool Permissions"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},

		// --- Sensitive Information Disclosure ---
		"AI-006": { // Prompt/response logging without redaction
			{OWASPLLM, "LLM06", "Sensitive Information Disclosure"},
			{OWASPAgent, "AG04", "Data Exfiltration"},
			{NIST80053, "NIST AU-3", "Content of audit records"},
			{HIPAA, "HIPAA 164.312(b)", "Audit controls"},
		},
		"AI-007": { // PII sent to LLM without filtering
			{OWASPLLM, "LLM06", "Sensitive Information Disclosure"},
			{OWASPAgent, "AG04", "Data Exfiltration"},
			{NIST80053, "NIST AU-3", "Content of audit records"},
			{HIPAA, "HIPAA 164.312(b)", "Audit controls"},
		},
		"AI-013": { // Model context contains secrets
			{OWASPLLM, "LLM06", "Sensitive Information Disclosure"},
			{OWASPAgent, "AG04", "Data Exfiltration"},
			{NIST80053, "NIST AU-3", "Content of audit records"},
			{HIPAA, "HIPAA 164.312(b)", "Audit controls"},
		},
		"AI-016": { // Training data leakage risk
			{OWASPLLM, "LLM06", "Sensitive Information Disclosure"},
			{OWASPAgent, "AG04", "Data Exfiltration"},
			{NIST80053, "NIST AU-3", "Content of audit records"},
			{HIPAA, "HIPAA 164.312(b)", "Audit controls"},
		},

		// --- Supply Chain Vulnerabilities ---
		"AI-008": { // Unpinned model version
			{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
			{OWASPAgent, "AG05", "Supply Chain"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"AI-014": { // Unverified model source
			{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
			{OWASPAgent, "AG05", "Supply Chain"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"AI-019": { // Unverified prompt template source
			{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
			{OWASPAgent, "AG05", "Supply Chain"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"AI-020": { // Unverified plugin/extension
			{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
			{OWASPAgent, "AG05", "Supply Chain"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"AI-021": { // Unverified vector store
			{OWASPLLM, "LLM05", "Supply Chain Vulnerabilities"},
			{OWASPAgent, "AG05", "Supply Chain"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},

		// --- Model Denial of Service ---
		"AI-017": { // No rate limit on LLM endpoint
			{OWASPLLM, "LLM04", "Model Denial of Service"},
			{OWASPAgent, "AG07", "Resource Abuse"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},

		// =================================================================
		// Extended Secret Detection Rules (SEC-087 through SEC-160)
		// =================================================================

		// --- SEC-087 through SEC-100: Cloud/Infrastructure Secrets ---
		"SEC-087": { // Cloudflare Global API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-088": { // DigitalOcean Spaces Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-089": { // Fly.io API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-090": { // Vercel Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-091": { // Netlify Personal Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-092": { // PlanetScale API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-093": { // Pulumi Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-094": { // Snowflake Credentials
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-095": { // MongoDB Atlas API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-096": { // Render API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-097": { // Railway API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-098": { // Hetzner API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-099": { // Scaleway API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-100": { // Upstash API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-101 through SEC-106: Identity/Auth Secrets ---
		"SEC-101": { // Auth0 Management API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-102": { // Okta API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-103": { // Clerk Secret Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-104": { // Supabase Service Role Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-105": { // Firebase Service Account Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-106": { // Keycloak Admin Credentials
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-107 through SEC-112: Observability Secrets ---
		"SEC-107": { // Datadog Application Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-108": { // Sentry Auth Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-109": { // Elastic APM Secret Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-110": { // Splunk HEC Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-111": { // Honeycomb API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-112": { // Grafana Cloud API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-113 through SEC-122: AI/ML Secrets ---
		"SEC-113": { // Pinecone API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-114": { // Weaviate API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-115": { // Google Gemini API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-116": { // Mistral API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-117": { // Groq API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-118": { // Together AI API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-119": { // Perplexity API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-120": { // Voyage AI API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-121": { // Anyscale API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-122": { // Replicate API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-123 through SEC-135: Productivity/SaaS Secrets ---
		"SEC-123": { // Notion API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-124": { // Figma Personal Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-125": { // Jira API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-126": { // Confluence API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-127": { // Atlassian API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-128": { // CircleCI Personal Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-129": { // Linear API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-130": { // Airtable API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-131": { // Asana Personal Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-132": { // Monday.com API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-133": { // Intercom Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-134": { // HubSpot API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-135": { // Salesforce Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-136 through SEC-145: Financial/Crypto Secrets ---
		"SEC-136": { // Plaid Client Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-137": { // Coinbase API Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-138": { // Binance API Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-139": { // PayPal Client Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-140": { // Adyen API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-141": { // Recurly API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-142": { // Braintree Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-143": { // Wise API Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-144": { // Kraken API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-145": { // Blockchain.com API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-146 through SEC-155: Messaging/Email Secrets ---
		"SEC-146": { // Postmark Server Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-147": { // Resend API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-148": { // Pusher App Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-149": { // Ably API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-150": { // MessageBird API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-151": { // Vonage API Secret
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-152": { // Mailchimp API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-153": { // SparkPost API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-154": { // Brevo (Sendinblue) API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-155": { // Courier API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// --- SEC-156 through SEC-160: Miscellaneous Secrets ---
		"SEC-156": { // Mapbox Access Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-157": { // LaunchDarkly SDK Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-158": { // Segment Write Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-159": { // Amplitude API Key
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"SEC-160": { // Doppler Service Token
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},

		// =================================================================
		// Data Sensitivity / PII Rules (DATA-001 through DATA-012)
		// =================================================================

		"DATA-001": { // Email address in source code
			{HIPAA, "HIPAA 164.514", "De-identification of protected health information"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-002": { // Social Security Number
			{HIPAA, "HIPAA 164.514", "De-identification of protected health information"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-003": { // Credit card number
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-004": { // Phone number in source code
			{HIPAA, "HIPAA 164.514", "De-identification of protected health information"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-005": { // IP address in source code
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-006": { // Date of birth in source code
			{HIPAA, "HIPAA 164.514", "De-identification of protected health information"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-007": { // IBAN in source code
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-008": { // UK National Insurance number
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-009": { // Tax identification number
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-010": { // Health record identifier
			{HIPAA, "HIPAA 164.514", "De-identification of protected health information"},
			{HIPAA, "HIPAA 164.312(a)(1)", "Access control"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-011": { // Driver's license number
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"DATA-012": { // Passport number
			{NIST80053, "NIST SI-12", "Information management and retention"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},

		// =================================================================
		// Extended IaC Rules (IAC-186 through IAC-365)
		// =================================================================

		// --- IAC-186 through IAC-230: Ansible Rules ---
		"IAC-186": { // Ansible no_log missing for sensitive tasks
			{NIST80053, "NIST AU-2", "Event logging"},
			{CIS, "CIS 5.3", "Ensure sensitive data is not logged"},
			{OWASPTop, "OWASP A09:2021", "Security Logging and Monitoring Failures"},
		},
		"IAC-187": { // Ansible plaintext password in playbook
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-188": { // Ansible vault not used for secrets
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-189": { // Ansible become without become_user
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.3", "Ensure privilege escalation is scoped"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-190": { // Ansible shell/command module used instead of specific module
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{CIS, "CIS 5.3", "Use specific modules over shell/command"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-191": { // Ansible raw module usage
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{CIS, "CIS 5.3", "Avoid raw module usage"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-192": { // Ansible ignore_errors on security tasks
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{CIS, "CIS 5.3", "Do not ignore errors in security tasks"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-193": { // Ansible HTTP URL without checksum
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
		},
		"IAC-194": { // Ansible get_url without validate_certs
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
		},
		"IAC-195": { // Ansible pip install without version pin
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-196": { // Ansible package install with state latest
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-197": { // Ansible firewall rule too permissive
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{CIS, "CIS 5.2", "Restrict firewall rules"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
		},
		"IAC-198": { // Ansible SELinux/AppArmor disabled
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.3", "Ensure mandatory access control is enabled"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-199": { // Ansible sysctl security settings missing
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{CIS, "CIS 5.3", "Ensure kernel hardening parameters are set"},
			{OWASPTop, "OWASP A05:2021", "Security Misconfiguration"},
		},
		"IAC-200": { // Ansible SSH password authentication enabled
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{CIS, "CIS 5.3", "Disable SSH password authentication"},
			{OWASPTop, "OWASP A07:2021", "Identification and Authentication Failures"},
		},
		"IAC-201": { // Ansible SSH root login enabled
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.3", "Disable SSH root login"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-202": { // Ansible file permissions too open
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.3", "Ensure restrictive file permissions"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"IAC-203": { // Ansible service running as root
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.3", "Ensure services run as non-root user"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-204": { // Ansible unencrypted communication
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-205": { // Ansible weak SSL/TLS version
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-206": { // Ansible audit logging not configured
			{NIST80053, "NIST AU-2", "Event logging"},
			{CIS, "CIS 5.3", "Ensure audit logging is configured"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-207": { // Ansible cron job without logging
			{NIST80053, "NIST AU-2", "Event logging"},
			{CIS, "CIS 5.3", "Ensure cron jobs are logged"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-208": { // Ansible NTP not configured
			{NIST80053, "NIST AU-8", "Time stamps"},
			{CIS, "CIS 5.3", "Ensure NTP is configured for time synchronization"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-209": { // Ansible unattended upgrades disabled
			{NIST80053, "NIST SI-2", "Flaw remediation"},
			{CIS, "CIS 5.3", "Ensure automatic security updates are enabled"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-210": { // Ansible hosts file with inline passwords
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-211": { // Ansible privilege escalation without password
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.3", "Ensure privilege escalation requires authentication"},
			{OWASPTop, "OWASP A07:2021", "Identification and Authentication Failures"},
		},
		"IAC-212": { // Ansible git module without version pin
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-213": { // Ansible docker_container privileged mode
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.2.1", "Minimize admission of privileged containers"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-214": { // Ansible user module without password hash
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
		},
		"IAC-215": { // Ansible lineinfile with password
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-216": { // Ansible template with hardcoded credentials
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-217": { // Ansible win_shell usage
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{CIS, "CIS 5.3", "Use specific Windows modules over win_shell"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-218": { // Ansible delegate_to localhost with become
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.3", "Ensure local privilege escalation is controlled"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-219": { // Ansible community module without FQCN
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-220": { // Ansible galaxy role without version pin
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-221": { // Ansible environment variables with secrets
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-222": { // Ansible debug module exposing variables
			{NIST80053, "NIST AU-2", "Event logging"},
			{OWASPTop, "OWASP A09:2021", "Security Logging and Monitoring Failures"},
			{CIS, "CIS 5.3", "Ensure debug output does not expose secrets"},
		},
		"IAC-223": { // Ansible connection plugin without encryption
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-224": { // Ansible disk encryption not configured
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
		},
		"IAC-225": { // Ansible swap not disabled for K8s nodes
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{CIS, "CIS 5.3", "Ensure swap is disabled on Kubernetes nodes"},
		},
		"IAC-226": { // Ansible PAM configuration insecure
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{CIS, "CIS 5.3", "Ensure PAM is properly configured"},
			{OWASPTop, "OWASP A07:2021", "Identification and Authentication Failures"},
		},
		"IAC-227": { // Ansible AIDE/integrity monitoring not configured
			{NIST80053, "NIST SI-7", "Software, firmware, and information integrity"},
			{CIS, "CIS 5.3", "Ensure file integrity monitoring is configured"},
			{SOC2, "SOC2 CC7.1", "Detect and monitor changes"},
		},
		"IAC-228": { // Ansible fail2ban/intrusion prevention not configured
			{NIST80053, "NIST SI-4", "Information system monitoring"},
			{CIS, "CIS 5.3", "Ensure intrusion prevention is configured"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-229": { // Ansible rsyslog/syslog not configured
			{NIST80053, "NIST AU-2", "Event logging"},
			{CIS, "CIS 5.3", "Ensure centralized logging is configured"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-230": { // Ansible kernel module loading unrestricted
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{CIS, "CIS 5.3", "Restrict kernel module loading"},
			{OWASPTop, "OWASP A05:2021", "Security Misconfiguration"},
		},

		// --- IAC-231 through IAC-245: Kustomize Rules ---
		"IAC-231": { // Kustomize image without digest
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{CIS, "CIS 5.5.1", "Ensure container images use fixed digests"},
		},
		"IAC-232": { // Kustomize remote base without pin
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-233": { // Kustomize secret generator with plaintext
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-234": { // Kustomize configMap with sensitive data
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-235": { // Kustomize patch removes security context
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 5.2.1", "Ensure security context is preserved"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-236": { // Kustomize namespace override to default
			{CIS, "CIS 5.7.1", "Ensure the default namespace is not actively used"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-237": { // Kustomize common labels missing
			{NIST80053, "NIST CM-8", "Information system component inventory"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-238": { // Kustomize resource limits not patched
			{CIS, "CIS 5.4.1", "Ensure resource limits are set on containers"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-239": { // Kustomize RBAC not configured
			{CIS, "CIS 5.1.1", "Ensure RBAC is properly configured"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-240": { // Kustomize network policy missing
			{CIS, "CIS 5.3.2", "Ensure NetworkPolicy is configured"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-241": { // Kustomize pod security standard missing
			{CIS, "CIS 5.2.1", "Ensure PodSecurity standards are configured"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-242": { // Kustomize HPA not configured
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-243": { // Kustomize service account not scoped
			{CIS, "CIS 5.1.6", "Ensure service accounts are scoped"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{NIST80053, "NIST CM-6", "Configuration settings"},
		},
		"IAC-244": { // Kustomize ingress without TLS
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-245": { // Kustomize strategic merge patch vulnerability
			{NIST80053, "NIST CM-6", "Configuration settings"},
			{OWASPTop, "OWASP A05:2021", "Security Misconfiguration"},
			{CIS, "CIS 5.3", "Ensure patches do not introduce vulnerabilities"},
		},

		// --- IAC-246 through IAC-265: Serverless Framework Rules ---
		"IAC-246": { // Serverless IAM role with wildcard permissions
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 1.16", "Ensure IAM policies do not allow full * admin privileges"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-247": { // Serverless function without VPC
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{CIS, "CIS 5.2", "Ensure Lambda functions are in a VPC"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-248": { // Serverless function with public endpoint
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-249": { // Serverless environment variable with secret
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-250": { // Serverless function timeout too high
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-251": { // Serverless function memory over-provisioned
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-252": { // Serverless API Gateway without authentication
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"IAC-253": { // Serverless function without encryption at rest
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
		},
		"IAC-254": { // Serverless function without tracing
			{NIST80053, "NIST AU-2", "Event logging"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
			{OWASPTop, "OWASP A09:2021", "Security Logging and Monitoring Failures"},
		},
		"IAC-255": { // Serverless DLQ not configured
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-256": { // Serverless reserved concurrency not set
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-257": { // Serverless HTTP API without CORS restriction
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{OWASPTop, "OWASP A05:2021", "Security Misconfiguration"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
		},
		"IAC-258": { // Serverless plugin from untrusted source
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-259": { // Serverless layer without version pin
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-260": { // Serverless function with admin policy
			{NIST80053, "NIST AC-6", "Least privilege"},
			{CIS, "CIS 1.16", "Ensure IAM policies do not allow full * admin privileges"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
		},
		"IAC-261": { // Serverless SQS trigger without encryption
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-262": { // Serverless S3 trigger without event filtering
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-263": { // Serverless WebSocket without authorization
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
		},
		"IAC-264": { // Serverless custom domain without TLS
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-265": { // Serverless CloudWatch logs not encrypted
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{NIST80053, "NIST AU-2", "Event logging"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
		},

		// --- IAC-266 through IAC-290: Expanded Terraform Rules ---
		"IAC-266": { // TF GCP firewall allows all ingress
			{CIS, "CIS 5.2", "Ensure no firewall rules allow ingress from 0.0.0.0/0"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-267": { // TF GCP Cloud SQL public IP
			{CIS, "CIS 2.3.2", "Ensure Cloud SQL instances are not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-268": { // TF GCP Cloud SQL no SSL
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-269": { // TF GCP Cloud Storage uniform access disabled
			{CIS, "CIS 2.1.5", "Ensure uniform bucket-level access is enabled"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-270": { // TF GCP KMS key rotation disabled
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{PCIDSS, "PCI-DSS 3.6", "Key management procedures"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-271": { // TF GCP logging not enabled
			{CIS, "CIS 3.1", "Ensure logging is enabled for all services"},
			{NIST80053, "NIST AU-2", "Event logging"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-272": { // TF GCP VPC flow logs disabled
			{CIS, "CIS 3.9", "Ensure VPC flow logging is enabled"},
			{NIST80053, "NIST AU-2", "Event logging"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-273": { // TF GCP IAM binding to allUsers
			{CIS, "CIS 1.16", "Ensure IAM bindings do not grant access to allUsers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
		},
		"IAC-274": { // TF GCP Compute instance with default service account
			{CIS, "CIS 1.16", "Ensure instances do not use default service account"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-275": { // TF GCP Compute instance with full API access scope
			{CIS, "CIS 1.16", "Ensure instances do not have full API access scope"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
		},
		"IAC-276": { // TF Azure storage account HTTP access
			{CIS, "CIS 3.1", "Ensure secure transfer required is enabled"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-277": { // TF Azure storage account public access
			{CIS, "CIS 2.1.5", "Ensure storage accounts deny public access"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
		},
		"IAC-278": { // TF Azure SQL server no audit
			{CIS, "CIS 3.1", "Ensure auditing is enabled for Azure SQL"},
			{PCIDSS, "PCI-DSS 10.1", "Implement audit trails"},
			{NIST80053, "NIST AU-2", "Event logging"},
		},
		"IAC-279": { // TF Azure SQL TDE disabled
			{CIS, "CIS 2.3.1", "Ensure TDE is enabled for Azure SQL"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-280": { // TF Azure NSG allows all inbound
			{CIS, "CIS 5.2", "Ensure NSG does not allow all inbound traffic"},
			{PCIDSS, "PCI-DSS 1.2.1", "Restrict inbound/outbound traffic"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-281": { // TF Azure Key Vault soft delete disabled
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{PCIDSS, "PCI-DSS 3.6", "Key management procedures"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-282": { // TF Azure Key Vault purge protection disabled
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{PCIDSS, "PCI-DSS 3.6", "Key management procedures"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-283": { // TF Azure App Service HTTPS only disabled
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-284": { // TF Azure App Service minimum TLS version
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{CIS, "CIS 2.1.2", "Ensure minimum TLS version is set"},
		},
		"IAC-285": { // TF Azure Network Watcher disabled
			{CIS, "CIS 3.9", "Ensure Network Watcher is enabled"},
			{NIST80053, "NIST SI-4", "Information system monitoring"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-286": { // TF AWS Cognito without MFA
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
			{OWASPTop, "OWASP A07:2021", "Identification and Authentication Failures"},
		},
		"IAC-287": { // TF AWS EKS public endpoint
			{CIS, "CIS 5.2", "Ensure EKS cluster endpoint is not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-288": { // TF AWS EKS secrets encryption disabled
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{CIS, "CIS 2.1.1", "Ensure EKS secrets are encrypted"},
		},
		"IAC-289": { // TF AWS EKS logging disabled
			{CIS, "CIS 3.1", "Ensure EKS control plane logging is enabled"},
			{NIST80053, "NIST AU-2", "Event logging"},
			{SOC2, "SOC2 CC7.2", "Monitor system components"},
		},
		"IAC-290": { // TF AWS MSK encryption in transit disabled
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// --- IAC-291 through IAC-310: Expanded Kubernetes Rules ---
		"IAC-291": { // K8s pod with shareProcessNamespace
			{CIS, "CIS 5.2.2", "Minimize containers sharing process namespace"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-292": { // K8s container with SYS_ADMIN capability
			{CIS, "CIS 5.2.7", "Minimize admission of containers with SYS_ADMIN"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-293": { // K8s container with NET_RAW capability
			{CIS, "CIS 5.2.7", "Minimize admission of containers with NET_RAW"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-294": { // K8s pod without seccomp profile
			{CIS, "CIS 5.2.9", "Ensure seccomp profile is set"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-295": { // K8s pod without AppArmor profile
			{CIS, "CIS 5.2.9", "Ensure AppArmor profile is set"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-296": { // K8s ClusterRole with wildcard resources
			{CIS, "CIS 5.1.1", "Ensure ClusterRoles do not use wildcard resources"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-297": { // K8s ClusterRoleBinding to default service account
			{CIS, "CIS 5.1.5", "Ensure default service accounts are not actively used"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-298": { // K8s PodSecurityPolicy not enforced
			{CIS, "CIS 5.2.1", "Ensure PodSecurityPolicy/Standards are enforced"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-299": { // K8s etcd not encrypted
			{CIS, "CIS 2.1", "Ensure etcd encryption is enabled"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
		},
		"IAC-300": { // K8s API server anonymous auth enabled
			{CIS, "CIS 5.1.1", "Ensure anonymous auth is disabled on API server"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{OWASPTop, "OWASP A07:2021", "Identification and Authentication Failures"},
		},
		"IAC-301": { // K8s NetworkPolicy not defined
			{CIS, "CIS 5.3.2", "Ensure NetworkPolicy is configured"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-302": { // K8s Ingress without TLS
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-303": { // K8s pod liveness probe missing
			{CIS, "CIS 5.4.1", "Ensure liveness probes are configured"},
			{NIST80053, "NIST SI-6", "Security function verification"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-304": { // K8s pod readiness probe missing
			{CIS, "CIS 5.4.1", "Ensure readiness probes are configured"},
			{NIST80053, "NIST SI-6", "Security function verification"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-305": { // K8s deployment without rolling update strategy
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-306": { // K8s external secrets operator misconfigured
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-307": { // K8s pod topology spread constraints missing
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-308": { // K8s container with writable /proc
			{CIS, "CIS 5.2.8", "Ensure /proc is read-only"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-309": { // K8s privileged port binding (<1024)
			{CIS, "CIS 5.2.7", "Minimize use of privileged ports"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-310": { // K8s emptyDir volume without size limit
			{CIS, "CIS 5.4.1", "Ensure emptyDir volumes have size limits"},
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},

		// --- IAC-311 through IAC-330: Expanded GitHub Actions Rules ---
		"IAC-311": { // GHA workflow_dispatch without input validation
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-312": { // GHA action with mutable tag
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-313": { // GHA GITHUB_TOKEN with excessive permissions
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-314": { // GHA runner without timeout
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-315": { // GHA hardcoded secret in workflow
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
		},
		"IAC-316": { // GHA cache poisoning risk
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-317": { // GHA workflow without concurrency control
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-318": { // GHA third-party action without review
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-319": { // GHA environment without protection rules
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-320": { // GHA OpenID Connect not used for cloud auth
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{OWASPTop, "OWASP A07:2021", "Identification and Authentication Failures"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
		},
		"IAC-321": { // GHA reusable workflow without version pin
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-322": { // GHA matrix strategy without fail-fast
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-323": { // GHA upload-artifact with sensitive paths
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-324": { // GHA download-artifact without verification
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-325": { // GHA container job without image pin
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
			{CIS, "CIS 5.5.1", "Ensure container images use fixed tags"},
		},
		"IAC-326": { // GHA secrets inherited without scoping
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
		},
		"IAC-327": { // GHA step without conditional check
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-328": { // GHA cron trigger without branch filter
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-329": { // GHA deployment without rollback strategy
			{NIST80053, "NIST CP-10", "Information system recovery and reconstitution"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-330": { // GHA composite action with shell injection risk
			{NIST80053, "NIST SI-10", "Information input validation"},
			{OWASPTop, "OWASP A03:2021", "Injection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},

		// --- IAC-331 through IAC-345: Expanded CloudFormation Rules ---
		"IAC-331": { // CFN EC2 instance without IMDSv2
			{CIS, "CIS 5.6", "Ensure IMDSv2 is required for EC2 instances"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{OWASPTop, "OWASP A05:2021", "Security Misconfiguration"},
		},
		"IAC-332": { // CFN ElastiCache not encrypted in transit
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-333": { // CFN ElastiCache not encrypted at rest
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
		},
		"IAC-334": { // CFN Neptune not encrypted
			{CIS, "CIS 2.4", "Ensure Neptune clusters are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-335": { // CFN Redshift not encrypted
			{CIS, "CIS 2.4", "Ensure Redshift clusters are encrypted"},
			{PCIDSS, "PCI-DSS 3.4", "Render PAN unreadable anywhere it is stored"},
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
		},
		"IAC-336": { // CFN Redshift publicly accessible
			{CIS, "CIS 5.2", "Ensure Redshift clusters are not publicly accessible"},
			{PCIDSS, "PCI-DSS 1.3", "Prohibit direct public access"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-337": { // CFN ECR lifecycle policy missing
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{NIST80053, "NIST CM-8", "Information system component inventory"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},
		"IAC-338": { // CFN ECS task execution role too broad
			{CIS, "CIS 1.16", "Ensure ECS task roles follow least privilege"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{PCIDSS, "PCI-DSS 7.1.2", "Restrict access to least privileges"},
		},
		"IAC-339": { // CFN Cognito user pool without MFA
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
			{OWASPTop, "OWASP A07:2021", "Identification and Authentication Failures"},
		},
		"IAC-340": { // CFN Secrets Manager without rotation
			{NIST80053, "NIST IA-5", "Authenticator management"},
			{PCIDSS, "PCI-DSS 8.2", "Proper authentication management"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-341": { // CFN S3 bucket without lifecycle policy
			{NIST80053, "NIST CP-9", "Information system backup"},
			{NIST80053, "NIST SI-12", "Information management and retention"},
		},
		"IAC-342": { // CFN KMS key without rotation
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{PCIDSS, "PCI-DSS 3.6", "Key management procedures"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},
		"IAC-343": { // CFN ALB without WAF
			{NIST80053, "NIST SC-7", "Boundary protection"},
			{PCIDSS, "PCI-DSS 6.6", "Address new threats and vulnerabilities"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-344": { // CFN ALB access logging disabled
			{CIS, "CIS 3.1", "Ensure ALB access logging is enabled"},
			{PCIDSS, "PCI-DSS 10.1", "Implement audit trails"},
			{NIST80053, "NIST AU-2", "Event logging"},
		},
		"IAC-345": { // CFN RDS without backup retention
			{NIST80053, "NIST CP-9", "Information system backup"},
			{PCIDSS, "PCI-DSS 10.7", "Retain audit trail history"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
		},

		// --- IAC-346 through IAC-355: Expanded Helm Chart Rules ---
		"IAC-346": { // Helm horizontal pod autoscaler missing
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{CIS, "CIS 5.4.1", "Ensure HPA is configured for scaling"},
		},
		"IAC-347": { // Helm pod priority class missing
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-348": { // Helm topology spread constraints missing
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-349": { // Helm service mesh sidecar not injected
			{NIST80053, "NIST SC-8", "Transmission confidentiality"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-350": { // Helm external-dns without policy restrict
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A05:2021", "Security Misconfiguration"},
		},
		"IAC-351": { // Helm cert-manager ClusterIssuer insecure
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{PCIDSS, "PCI-DSS 4.1", "Use strong cryptography during transmission"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"IAC-352": { // Helm init container with elevated privileges
			{CIS, "CIS 5.2.1", "Minimize privileged init containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-353": { // Helm volume claim without storage class
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-354": { // Helm RBAC aggregation rules too broad
			{CIS, "CIS 5.1.1", "Ensure RBAC aggregation is scoped"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{SOC2, "SOC2 CC6.3", "Role-based access control"},
		},
		"IAC-355": { // Helm admission webhook without failurePolicy
			{NIST80053, "NIST AC-3", "Access enforcement"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
			{CIS, "CIS 5.2.1", "Ensure admission webhooks have failure policies"},
		},

		// --- IAC-356 through IAC-365: Expanded Compose/Docker Rules ---
		"IAC-356": { // Compose tmpfs without size limit
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{CIS, "CIS 5.14", "Ensure tmpfs mounts have size limits"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-357": { // Compose ulimits not configured
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{CIS, "CIS 5.14", "Ensure ulimits are configured for containers"},
		},
		"IAC-358": { // Compose device mapping to host
			{CIS, "CIS 5.2.3", "Minimize host device access from containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-359": { // Compose ipc mode host
			{CIS, "CIS 5.2.3", "Minimize containers sharing host IPC"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-360": { // Compose security_opt not configured
			{CIS, "CIS 5.2.9", "Ensure security options are configured"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-361": { // Compose read_only not enabled
			{CIS, "CIS 5.2.8", "Ensure containers have read-only root filesystem"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-362": { // Compose healthcheck not defined
			{CIS, "CIS 4.6", "Ensure HEALTHCHECK instructions have been added"},
			{NIST80053, "NIST SI-6", "Security function verification"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-363": { // Compose depends_on without condition
			{NIST80053, "NIST SC-5", "Denial of service protection"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-364": { // Compose network mode bridge without isolation
			{CIS, "CIS 5.2.4", "Ensure network isolation is configured"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
			{SOC2, "SOC2 CC6.6", "Boundary protection"},
		},
		"IAC-365": { // Compose volume driver not specified
			{NIST80053, "NIST SC-28", "Protection of information at rest"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
	}
}
