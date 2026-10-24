package iso27001

// OrgItem is a record, policy or process an ISO/IEC 27001 assessment needs and
// a code repository cannot show. They are phrased as things to produce or
// point to, in the order a team usually meets them.
type OrgItem struct {
	ID string `json:"id"`
	// Reference cites the management-system clause or Annex A control the item
	// belongs to, by number only.
	Reference string `json:"reference"`
	Title     string `json:"title"`
	Needed    string `json:"needed"`
	// Controls lists the Annex A controls in this assessment that depend on it.
	// Filled in by Assess.
	Controls []string `json:"controls,omitempty"`
}

// orgItems is the checklist, in presentation order. The first group is the
// management system itself and applies whatever the scan found.
var orgItems = []OrgItem{
	{ID: "ORG-SCOPE", Reference: "Clause 4.3", Title: "ISMS scope",
		Needed: "A statement of what the information security management system covers, and where this repository and the product built from it sit inside that boundary."},
	{ID: "ORG-POLICY", Reference: "Clause 5.2; A.5.1", Title: "Information security policy",
		Needed: "An approved policy and the topic-specific policies beneath it, communicated to the people they apply to."},
	{ID: "ORG-ROLES", Reference: "Clause 5.3; A.5.2", Title: "Roles and responsibilities",
		Needed: "Named owners for information security, including who owns security of this application."},
	{ID: "ORG-RISK", Reference: "Clauses 6.1.2, 6.1.3", Title: "Risk assessment, treatment and Statement of Applicability",
		Needed: "A documented risk method, a risk register that includes this application, treatment decisions with owners (including any accepted risk), and the Statement of Applicability that records which Annex A controls apply and why."},
	{ID: "ORG-OBJECTIVES", Reference: "Clause 6.2", Title: "Security objectives",
		Needed: "Measurable objectives and the records of how they are monitored."},
	{ID: "ORG-TRAINING", Reference: "Clauses 7.2, 7.3; A.6.3", Title: "Competence, awareness and training",
		Needed: "Records that developers and operators have the skills the role needs, including secure-coding training."},
	{ID: "ORG-DOCS", Reference: "Clause 7.5", Title: "Documented information control",
		Needed: "How documents and records are created, approved, versioned and retained, so that this assessment material is itself a controlled record."},
	{ID: "ORG-AUDIT", Reference: "Clauses 9.2, 9.3", Title: "Internal audit and management review",
		Needed: "An audit programme with reports, and minutes of management review of the system's performance."},
	{ID: "ORG-IMPROVE", Reference: "Clause 10", Title: "Nonconformity and continual improvement",
		Needed: "A record of nonconformities, corrective actions and their closure."},
	{ID: "ORG-ASSETS", Reference: "A.5.9; A.5.10", Title: "Asset ownership",
		Needed: "An inventory covering information, services and data stores beyond software components, each with an owner."},
	{ID: "ORG-DATA-CLASS", Reference: "A.5.12; A.5.13; A.5.10", Title: "Data classification and handling",
		Needed: "A classification scheme, labelling and handling rules, and evidence they are applied to this application's data."},
	{ID: "ORG-PRIVACY", Reference: "A.5.34", Title: "Privacy records",
		Needed: "Records of processing, lawful basis, retention rules and data-protection impact assessments for personal data this application handles."},
	{ID: "ORG-ACCESS", Reference: "A.5.15; A.5.18; A.8.2; A.8.3; A.8.4", Title: "Access control and access reviews",
		Needed: "An access control policy, evidence of periodic access reviews, joiner/mover/leaver records, and the repository-host settings that restrict who can read and change source code."},
	{ID: "ORG-SUPPLIERS", Reference: "A.5.19; A.5.20; A.5.21; A.5.22", Title: "Supplier agreements and reviews",
		Needed: "Supplier security requirements in contracts, assessments of the suppliers the software bill of materials implies, and how supplier service changes are monitored."},
	{ID: "ORG-CLOUD", Reference: "A.5.23", Title: "Cloud service governance",
		Needed: "A cloud-use policy, the shared-responsibility split agreed with each provider, and exit arrangements."},
	{ID: "ORG-INCIDENT", Reference: "A.5.24 to A.5.28", Title: "Incident management",
		Needed: "A documented incident process, roles, and records of incidents and exercises, including how a vulnerability disclosed in a dependency is handled."},
	{ID: "ORG-CONTINUITY", Reference: "A.5.29; A.5.30; A.8.13; A.8.14", Title: "Continuity, backup and redundancy",
		Needed: "Continuity plans and backup/restore test records for the systems this application runs on."},
	{ID: "ORG-MONITORING", Reference: "A.8.15; A.8.16", Title: "Logging and monitoring",
		Needed: "Evidence that production logs are collected, protected and reviewed, and that anomalies raise alerts someone acts on."},
	{ID: "ORG-CRYPTO", Reference: "A.8.24", Title: "Cryptography and key management",
		Needed: "A cryptography policy and records of how keys and secrets are generated, stored, rotated and revoked."},
	{ID: "ORG-VULN-PROCESS", Reference: "A.8.8", Title: "Vulnerability management process",
		Needed: "Time-to-remediate targets, triage records, and the approval trail for any vulnerability left unfixed."},
	{ID: "ORG-CHANGE", Reference: "A.8.9; A.8.32", Title: "Change and configuration management",
		Needed: "A change process with approvals, and configuration baselines that production is compared against."},
	{ID: "ORG-SDLC", Reference: "A.8.25; A.8.28", Title: "Secure development procedure",
		Needed: "A defined development life cycle with security gates, code review rules, and evidence they run on every change (for example CI configuration and review records)."},
	{ID: "ORG-REQUIREMENTS", Reference: "A.8.26", Title: "Application security requirements",
		Needed: "Documented security requirements for this application and traceability from them to tests."},
	{ID: "ORG-ARCHITECTURE", Reference: "A.8.27", Title: "Architecture principles and threat modelling",
		Needed: "Documented secure-engineering principles and threat models or design reviews for this application."},
	{ID: "ORG-TESTING", Reference: "A.8.29", Title: "Security testing plan and results",
		Needed: "A testing plan, penetration test reports and acceptance-test records, with findings tracked to closure."},
}
