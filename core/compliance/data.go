package compliance

// complianceData returns the embedded compliance mapping data for all rules.
// Each rule is mapped to its applicable CIS, PCI-DSS, SOC2, NIST-800-53,
// HIPAA, and OWASP Top 10 controls.
func complianceData() map[string][]FrameworkControl {
	return map[string][]FrameworkControl{
		// =====================================================================
		// Secret Detection Rules (SEC-*)
		// =====================================================================
		"SEC-001": {
			{CIS, "CIS 16.4", "Encrypt or hash all authentication credentials"},
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{SOC2, "SOC2 CC6.1", "Logical and physical access controls"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{HIPAA, "HIPAA 164.312(a)(2)(iv)", "Encryption and decryption"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-002": {
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{NIST80053, "NIST SC-12", "Cryptographic key establishment and management"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},
		"SEC-006": {
			{PCIDSS, "PCI-DSS 6.5.3", "Insecure cryptographic storage"},
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
		},

		// Generic secret rules map broadly to credential management controls.
		"SEC-050": {
			{OWASPTop, "OWASP A02:2021", "Cryptographic Failures"},
			{NIST80053, "NIST IA-5", "Authenticator management"},
		},

		// =====================================================================
		// IaC Rules (IAC-*)
		// =====================================================================
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
		},
		"IAC-007": { // K8s privileged pod
			{CIS, "CIS 5.2.1", "Minimize admission of privileged containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
			{OWASPTop, "OWASP A04:2021", "Insecure Design"},
		},
		"IAC-008": { // K8s host network
			{CIS, "CIS 5.2.4", "Minimize admission of containers with hostNetwork"},
			{NIST80053, "NIST AC-4", "Information flow enforcement"},
		},
		"IAC-009": { // K8s privilege escalation
			{CIS, "CIS 5.2.5", "Minimize admission with allowPrivilegeEscalation"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-010": { // K8s root user
			{CIS, "CIS 5.2.6", "Minimize admission of root containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-011": { // GHA pull_request_target
			{NIST80053, "NIST SA-11", "Developer security testing"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-013": { // GHA unpinned action
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"IAC-014": { // GHA write-all
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-019": { // Compose privileged
			{CIS, "CIS 5.2.1", "Minimize admission of privileged containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
		"IAC-021": { // Docker socket mount
			{CIS, "CIS 5.31", "Ensure Docker socket is not mounted inside containers"},
			{NIST80053, "NIST AC-6", "Least privilege"},
		},
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

		// =====================================================================
		// Vulnerability Rules (VULN-*)
		// =====================================================================
		"VULN-001": {
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

		// =====================================================================
		// Container Rules (CONT-*)
		// =====================================================================
		"CONT-001": {
			{CIS, "CIS 4.7", "Ensure update instructions are not used alone"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A08:2021", "Software and Data Integrity Failures"},
		},
		"CONT-002": {
			{CIS, "CIS 4.7", "Ensure update instructions are not used alone"},
			{NIST80053, "NIST SA-12", "Supply chain protection"},
			{OWASPTop, "OWASP A06:2021", "Vulnerable and Outdated Components"},
		},

		// =====================================================================
		// License Rules (LIC-*)
		// =====================================================================
		"LIC-001": {
			{SOC2, "SOC2 CC9.2", "Risk assessment and management"},
		},

		// =====================================================================
		// AI Security Rules (AI-*)
		// =====================================================================
		"AI-001": {
			{OWASPTop, "OWASP A03:2021", "Injection"},
			{NIST80053, "NIST SI-10", "Information input validation"},
		},
		"AI-002": {
			{OWASPTop, "OWASP A03:2021", "Injection"},
			{NIST80053, "NIST SI-10", "Information input validation"},
		},
		"AI-003": {
			{NIST80053, "NIST AU-3", "Content of audit records"},
			{HIPAA, "HIPAA 164.312(b)", "Audit controls"},
		},
		"AI-005": {
			{OWASPTop, "OWASP A01:2021", "Broken Access Control"},
			{NIST80053, "NIST AC-3", "Access enforcement"},
		},
	}
}
