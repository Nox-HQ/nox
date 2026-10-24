package iso27001

// Standard names the framework edition every control number below belongs to.
// Annex A was renumbered in 2022; the 2013 numbering (A.12.6.1 and so on) is
// not used anywhere in this package.
const Standard = "ISO/IEC 27001:2022"

// sourceKind says which nox output a piece of evidence comes from.
type sourceKind int

const (
	fromFindings sourceKind = iota
	fromSBOM
	fromAI
	fromScanRecord
)

// source is one place a control's evidence comes from.
type source struct {
	kind  sourceKind
	label string
	// scope is the nox scan scope whose absence means the checks never ran
	// (see core/scope.go). Empty for sources that are not scope-bound.
	scope string
	// prefixes select findings by rule ID prefix; cwes select by the CWE the
	// finding carries. A finding matching either is evidence.
	prefixes []string
	cwes     []string
	// degradeKinds name scan degradations that make this source incomplete.
	degradeKinds []string
	// anywhere marks checks that apply to every file, so an empty result is
	// meaningful by itself (secret scanning). subjectFromSBOM marks checks
	// whose subject is the dependency set: an empty result counts only when the
	// SBOM shows dependencies existed. Every other source covers files that may
	// not be in the repository at all (infrastructure code, say), and an empty
	// result from one of those cannot be told from a scan with nothing to read.
	anywhere        bool
	subjectFromSBOM bool
	// networkLookup marks checks that query an external advisory source. A
	// scan that skipped the lookup (--no-osv) leaves the same outputs as one
	// whose lookup found nothing, so an empty result cannot be read as clean.
	networkLookup bool
}

// controlDef is the static description of one Annex A control: which scan
// evidence supports it, and what that evidence can never show.
type controlDef struct {
	id    string
	title string
	theme string
	// sources is empty for a control the scan cannot evidence at all.
	sources []source
	// indirect marks a control the scan touches only at one remove: its
	// evidence can support a conversation about the control but never be the
	// substance of it. An indirect control is never reported above limited.
	indirect bool
	// needsCapability names an analysis capability that must have answered at
	// least once for the evidence to be complete; empty when none is required.
	needsCapability string
	capabilityGap   string
	// limits is what the evidence cannot show, whatever the scan found. These
	// are fixed by the nature of the control and the scanner, not by the run.
	limits []string
	// org lists the organizational evidence (see org.go) the control needs.
	org []string
}

var (
	depKinds = []string{"osv_lookup", "lockfile_parse", "vuln_data_load"}

	cryptoCWEs = []string{
		"CWE-261", "CWE-295", "CWE-311", "CWE-312", "CWE-319", "CWE-321",
		"CWE-326", "CWE-327", "CWE-328", "CWE-330", "CWE-338", "CWE-759", "CWE-916",
	}
)

// controls is the Annex A mapping, in Annex A order. Titles are the 2022 short
// titles; no other standard text is reproduced here.
var controls = []controlDef{
	{
		id: "A.5.9", title: "Inventory of information and other associated assets", theme: "Organizational",
		sources: []source{
			{kind: fromSBOM, label: "Software bill of materials", scope: "deps"},
			{kind: fromAI, label: "AI component inventory", scope: "ai"},
		},
		indirect: true,
		limits: []string{
			"Only software components and AI models/agents declared in this repository are listed; information assets, data stores, hardware and services are not.",
			"An inventory shows what exists, not who owns it, how it is classified, or that it is kept current.",
		},
		org: []string{"ORG-ASSETS", "ORG-DATA-CLASS"},
	},
	{
		id: "A.5.17", title: "Authentication information", theme: "Organizational",
		sources: []source{
			{kind: fromFindings, label: "Secret scanning of the working tree", scope: "secrets", prefixes: []string{"SEC-"}, anywhere: true},
		},
		limits: []string{
			"A clean secret scan shows no recognizable credential was found in the scanned files; it does not show credentials are generated, stored, rotated or revoked well.",
			"Secrets already committed to git history are only covered when a history scan was run, which findings.json does not record.",
			"Password rules, multi-factor authentication and credential allocation are processes outside the repository.",
		},
		org: []string{"ORG-ACCESS", "ORG-CRYPTO"},
	},
	{
		id: "A.5.19", title: "Information security in supplier relationships", theme: "Organizational",
		sources: []source{
			{kind: fromSBOM, label: "Software bill of materials", scope: "deps"},
		},
		indirect: true,
		limits: []string{
			"The bill of materials names third-party software suppliers; it shows nothing about the agreements, assessments or monitoring that govern the relationship.",
		},
		org: []string{"ORG-SUPPLIERS"},
	},
	{
		id: "A.5.21", title: "Managing information security in the ICT supply chain", theme: "Organizational",
		sources: []source{
			{kind: fromSBOM, label: "Software bill of materials", scope: "deps"},
			{kind: fromFindings, label: "Supply-chain checks (slopsquatting, provenance, licenses, containers)", scope: "supply-chain",
				prefixes: []string{"SLOP-", "PROV-", "LIC-", "CONT-"}, degradeKinds: depKinds, subjectFromSBOM: true},
		},
		limits: []string{
			"Checks cover dependencies declared in lockfiles and manifests; build tooling, hosted services and vendored binaries outside them are not covered.",
			"Provenance and typosquat checks flag risk signals; they do not verify a supplier's own security practices.",
			"Requirements placed on suppliers and the process for acting on supply-chain change are not visible to a scan.",
		},
		org: []string{"ORG-SUPPLIERS", "ORG-VULN-PROCESS"},
	},
	{
		id: "A.5.23", title: "Information security for use of cloud services", theme: "Organizational",
		sources: []source{
			{kind: fromFindings, label: "Infrastructure-as-code configuration checks", scope: "iac", prefixes: []string{"IAC-"}},
		},
		limits: []string{
			"Only cloud configuration declared in files in this repository is checked; the deployed state of a cloud account is not observed.",
			"Choice of provider, the shared-responsibility split, contractual terms and exit arrangements are outside what a scan can see.",
		},
		org: []string{"ORG-CLOUD", "ORG-SUPPLIERS"},
	},
	{
		id: "A.5.34", title: "Privacy and protection of personal identifiable information (PII)", theme: "Organizational",
		sources: []source{
			{kind: fromFindings, label: "Sensitive-data handling checks", scope: "data", prefixes: []string{"DATA-"}},
		},
		limits: []string{
			"Checks look for patterns that suggest personal data is handled unsafely in code; they cannot decide what is personal data in your context.",
			"Lawful basis, records of processing, retention, data-subject rights and impact assessments are not visible to a scan.",
		},
		org: []string{"ORG-DATA-CLASS", "ORG-PRIVACY"},
	},
	{
		id: "A.8.4", title: "Access to source code", theme: "Technological",
		sources: []source{
			{kind: fromFindings, label: "Secret scanning (credentials that would expose code or systems)", scope: "secrets", prefixes: []string{"SEC-"}, anywhere: true},
		},
		indirect: true,
		limits: []string{
			"Nox does not see who can read or write the repository, branch protection, review requirements or access reviews; those are repository-host settings.",
			"The only technical evidence is indirect: whether credentials are committed to the working tree.",
		},
		org: []string{"ORG-ACCESS"},
	},
	{
		id: "A.8.8", title: "Management of technical vulnerabilities", theme: "Technological",
		sources: []source{
			{kind: fromFindings, label: "Dependency vulnerability checks against OSV.dev", scope: "deps",
				prefixes: []string{"VULN-"}, degradeKinds: depKinds, subjectFromSBOM: true, networkLookup: true},
			{kind: fromSBOM, label: "Software bill of materials", scope: "deps"},
		},
		limits: []string{
			"Only vulnerabilities in declared dependencies are covered; operating systems, base images not described in the repository, and running infrastructure are not.",
			"A finding is a published advisory against a package version. Whether the vulnerable code is reachable in your application is a separate question the finding states per case.",
			"Evidence of a vulnerability management process (who is told, how quickly it is fixed, which risks are accepted and by whom) is not in a scan.",
		},
		org: []string{"ORG-VULN-PROCESS", "ORG-RISK"},
	},
	{
		id: "A.8.9", title: "Configuration management", theme: "Technological",
		sources: []source{
			{kind: fromFindings, label: "Infrastructure and file-permission configuration checks", scope: "iac",
				prefixes: []string{"IAC-", "PERM-"}},
		},
		limits: []string{
			"Checks cover configuration written in this repository against known-risky settings; they are not a baseline you approved.",
			"Whether configuration in production matches the repository, and how changes to it are authorized, is not observed.",
		},
		org: []string{"ORG-CHANGE", "ORG-CLOUD"},
	},
	{
		id: "A.8.12", title: "Data leakage prevention", theme: "Technological",
		sources: []source{
			{kind: fromFindings, label: "Sensitive-data and secret-exposure checks", scope: "data", prefixes: []string{"DATA-", "SEC-"}, anywhere: true},
		},
		indirect: true,
		limits: []string{
			"Static checks find code that may expose data; they are not a data-leakage-prevention control operating on networks, endpoints or mail.",
			"Data classification and the rules for handling each class are organizational.",
		},
		org: []string{"ORG-DATA-CLASS"},
	},
	{
		id: "A.8.24", title: "Use of cryptography", theme: "Technological",
		sources: []source{
			{kind: fromFindings, label: "Weak or misused cryptography checks", scope: "code",
				prefixes: []string{"CRYPTO-"}, cwes: cryptoCWEs},
		},
		limits: []string{
			"Checks find weak algorithms, protocols and settings in code and configuration; they do not assess key generation, storage, rotation or retirement.",
			"A policy on cryptography and the records of how keys are managed are organizational.",
		},
		org: []string{"ORG-CRYPTO"},
	},
	{
		id: "A.8.25", title: "Secure development life cycle", theme: "Technological",
		sources: []source{
			{kind: fromScanRecord, label: "Record of the security scan itself"},
		},
		indirect: true,
		limits: []string{
			"One scan shows that a security check ran once. It does not show the check runs on every change, that findings block release, or that the rules of the life cycle are defined.",
		},
		org: []string{"ORG-SDLC", "ORG-CHANGE"},
	},
	{
		id: "A.8.26", title: "Application security requirements", theme: "Technological",
		limits: []string{
			"Requirements are written down by people before code exists. Nothing a scan produces states, or tests conformance to, your requirements.",
		},
		org: []string{"ORG-REQUIREMENTS"},
	},
	{
		id: "A.8.27", title: "Secure system architecture and engineering principles", theme: "Technological",
		sources: []source{
			{kind: fromAI, label: "AI component inventory (models, agents, tools)", scope: "ai"},
			{kind: fromFindings, label: "AI, agent and MCP architecture checks", scope: "ai",
				prefixes: []string{"AI-", "AGENT-", "AGENTFLOW-", "MCP-"}},
		},
		indirect: true,
		limits: []string{
			"Checks examine a few architectural risks in AI-enabled applications (tool exposure, trust boundaries); they are not a review of the architecture.",
			"Documented principles, threat models and design reviews are organizational.",
		},
		org: []string{"ORG-ARCHITECTURE"},
	},
	{
		id: "A.8.28", title: "Secure coding", theme: "Technological",
		sources: []source{
			{kind: fromFindings, label: "Static analysis of application code", scope: "code",
				prefixes: []string{"TAINT-", "VARIANT-", "MEMSAFE-", "HARDEN-"}},
		},
		limits: []string{
			"Static analysis finds a subset of defect classes in the languages it supports; absence of findings is not absence of defects.",
			"Coding standards, developer training and code review practice are organizational.",
		},
		org: []string{"ORG-SDLC", "ORG-TRAINING"},
	},
	{
		id: "A.8.29", title: "Security testing in development and acceptance", theme: "Technological",
		sources: []source{
			{kind: fromScanRecord, label: "Record of the security scan itself"},
		},
		needsCapability: "dynamic_verification",
		capabilityGap:   "No dynamic verification was performed in this scan: findings are static observations, none was confirmed exploitable or shown to be prevented. Run `nox attack` against a running target for runtime evidence.",
		limits: []string{
			"Static scanning is one kind of security testing. Penetration tests, acceptance tests and test plans are not produced by it.",
		},
		org: []string{"ORG-TESTING"},
	},
}
