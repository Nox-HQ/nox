
## Project Scaffold & Go Module Setup

Initialize Go module, set up directory structure (/core, /cli, /server, /ai-assist), configure golangci-lint, Makefile with build/test/lint targets, and GitHub Actions CI workflow. This is the foundation for all other features.

---

## File Discovery Engine

Core artifact discovery system that recursively walks a workspace, respects gitignore patterns, and classifies files by type (source, config, lockfile, container definition, AI component). Provides an extensible file classifier registry for adding new artifact types.

---

## Canonical Findings Model

Core data model for security findings with stable versioned fingerprinting (deterministic hash), explicit severity and confidence levels, precise source location (file, region, line, column), deduplication by fingerprint, and SARIF-compatible location model. This is the central data structure consumed by all reporters.

---

## YAML Rule Engine

Declarative rule system using YAML definitions with versioned rule IDs, deterministic matching, and pluggable matchers (regex, jsonpath, yamlpath, heuristic). Includes rule validation, testing support, and strictly no embedded code execution. Rules are the primary configuration mechanism for all analyzers.

---

## Secrets Scanner

Pattern-based analyzer for detecting secrets, API keys, tokens, and credentials in source files and configuration. Includes built-in rules for common secret patterns (AWS keys, GitHub tokens, private keys), configurable entropy-based detection, allowlist/ignore mechanism, and line-level location reporting.

---

## Dependency Scanner

Analyzer for lockfiles and dependency manifests (npm package-lock.json, Go go.sum, Python requirements.txt/poetry.lock, Ruby Gemfile.lock) that extracts package inventories with name/version/ecosystem, checks against OSV API for known vulnerabilities, and produces CycloneDX component entries for SBOM generation.

---

## SARIF Report Output

Generate SARIF 2.1.0 reports compatible with GitHub Code Scanning. One run per scan with full rule catalog populated from matched rules, fingerprints attached to results, and precise result locations. Must pass GitHub Code Scanning ingestion validation.

---

## SBOM Output (CycloneDX & SPDX)

Generate Software Bill of Materials in CycloneDX JSON (primary, sbom.cdx.json) and SPDX JSON (secondary, sbom.spdx.json) formats from dependency analysis. Component inventory sourced from dependency scanner with optional vulnerability enrichment via OSV.

---

## JSON Findings Output

Emit canonical findings.json with the full findings model, usable as machine-readable input for downstream tooling. Deterministic output ordering and schema versioning included.

---

## CLI Interface

Command-line interface with 'nox scan &lt;path&gt;' as the primary command. Supports output format selection (sarif, cdx, spdx, json, all), exit codes reflecting finding severity, quiet/verbose modes, and config file support (.nox.yaml).

---

## Infrastructure-as-Code Rules

Basic security rules for Terraform (public access, encryption), Dockerfiles (no root, pinned base images), and Kubernetes manifests (privilege escalation, host network). All defined as YAML-based rules consumed by the rule engine.

---

## AI Security Rules

First-class AI security scanning: detect prompt/RAG boundary violations, unsafe MCP/agent tool exposure, insecure prompt/response logging, unpinned model/prompt versions. Produces ai.inventory.json with extracted AI component inventory. This is a differentiating feature of Nox.

---

## MCP Server

Model Context Protocol server using mcp-go with stdio transport. Exposes read-only tools (scan, get-findings, get-sbom), workspace allowlisting, artifact serving via MCP resources, output size limits, and rate limiting. Agent-safe by default.

---

## Agent Assist Module (Optional)

Optional LLM-powered module built on agent-go that consumes findings and AI inventory to produce human-readable explanations. Strictly no side effects, never affects scan results, opt-in only, lives in a separate module boundary from core.

---

## Plugin gRPC Interface

Protobuf definitions and gRPC service contract for plugin manifests, tool invocations, and artifact exchange. Defines the PluginService with GetManifest, InvokeTool, and StreamArtifacts RPCs. Plugin manifests declare capabilities (analyzers, reporters, tools), safety requirements (network hosts, file paths, environment variables), and API version compatibility. All message types are versioned and backwards-compatible.

---

## Plugin Host Runtime

Core runtime that discovers plugin endpoints (local binaries, containers, remote gRPC), calls GetManifest to learn capabilities, validates safety constraints against host policy, manages plugin lifecycle (init, invoke, shutdown), and merges plugin results (findings, SBOM components, AI inventory entries) into Nox's unified outputs. Supports parallel plugin execution with configurable concurrency limits.

---

## Plugin Safety Engine

Host-enforced safety model that validates and constrains plugin behavior. Enforces scope allowlists (permitted network hosts/CIDRs, file path globs, environment variables), rate limits (requests per minute, bandwidth), concurrency caps, read-only defaults, artifact size limits, and secret redaction from plugin outputs. Destructive actions require explicit opt-in via nox.yaml. Safety violations are logged and cause plugin termination.

---

## Plugin SDK

Minimal SDK for plugin authors providing: versioned protobuf definitions, gRPC server scaffolding (Go initially, with extension points for other languages), manifest and capability declaration helpers, safety envelope parsing and enforcement utilities, artifact serialization helpers (findings, SBOM components, AI inventory entries), and a conformance test runner that validates plugin behavior against the contract. Includes a plugin template generator for bootstrapping new plugins.

---

## MCP Plugin Bridge

Expose plugin capabilities through the MCP server interface. Adds plugin.list tool (enumerate installed plugins and capabilities), plugin.call_tool tool (invoke a specific plugin tool with arguments), and plugin.read_resource tool (read plugin-provided resources). Supports convenience aliases that map friendly names to plugin tools (e.g., nox.dast.scan maps to a DAST plugin's scan tool). Plugin tools inherit workspace allowlisting and output size limits from the MCP server.

---

## Plugin Registry & Distribution

Registry client for discovering and installing plugins. Supports static index fetching from registry URLs, OCI artifact download with local caching and digest verification, semantic version resolution with compatibility constraints, and multiple registry sources (official Nox registry, community registries, enterprise private registries). Registry metadata includes plugin manifests, compatibility matrices, and trust information. Implements offline-friendly caching with TTL-based refresh.

---

## Plugin Trust & Verification

Signature validation and trust management for plugins. Verifies artifact signatures against configurable trust roots, checks content digests on download and before execution, validates API version compatibility between plugin and host, runs conformance tests as part of installation verification. Implements trust levels (verified: signed by known key, community: signed but unknown key, unverified: unsigned) with configurable minimum trust requirements. Enterprise deployments can mandate verified-only plugins.

---

## CLI Plugin Commands

CLI commands for managing registries and plugins. Registry commands: 'nox registry add <url>' (add registry source), 'nox registry list' (show configured registries), 'nox registry remove <name>' (remove registry). Plugin commands: 'nox plugin search <query>' (search registries), 'nox plugin info <name>' (show plugin details and trust status), 'nox plugin install <name>[@version]' (install with verification), 'nox plugin update [name]' (update one or all plugins), 'nox plugin list' (show installed plugins), 'nox plugin remove <name>' (uninstall), 'nox plugin call <name> <tool> [args]' (invoke plugin tool directly from CLI).

---

## Git History Scanning for Secrets

Scan git commit history for leaked secrets that were committed and later removed. Traverse commits using git rev-list, extract diffs with git diff-tree, run the secrets analyzer against historical content. Support depth limits (--history-depth), branch selection (--branch), and incremental scanning from a bookmark commit. Report findings with commit SHA, author, and date metadata. Critical for detecting secrets that exist in git history but not in the working tree. Integrates with existing secrets analyzer (938 rules) and findings model.

---

## Entropy-Based Secret Detection

Add Shannon entropy calculation as a complementary detection method alongside regex patterns. Implement an entropy matcher type in the rule engine that scores string segments and flags high-entropy values above configurable thresholds. Detect base64-encoded blobs, hex-encoded secrets, and random strings that don't match any known pattern. Integrate as a new matcher type ('entropy') in the MatcherRegistry alongside the existing regex matcher. Combine with assignment context (e.g., variable named 'secret' or 'password' with high-entropy value) to reduce false positives.

---

## Pre-commit Hook (nox protect)

Add a 'nox protect' command that installs a git pre-commit hook to prevent secrets from being committed. The hook scans only staged files (git diff --cached) for speed. Supports install/uninstall subcommands, .pre-commit-hooks.yaml for the pre-commit framework, and direct .git/hooks/pre-commit shell script generation. Fail-fast on any critical/high finding. Configurable severity threshold via .nox.yaml. Exit code 1 blocks the commit with a clear message showing what was found and how to suppress false positives.

---

## Custom Rules CLI Integration

Wire up the existing YAML rule loader (core/rules/loader.go) to the CLI via --rules flag on scan, diff, and protect commands. Load user-defined rules from a file or directory and merge them with built-in rules. Support .nox.yaml configuration for default rules paths. Validate custom rules at load time with clear error messages. This completes the custom rules story — the loader already exists but is unreachable from the CLI.

---

## Expand secrets rule library to 900+ detectors ✅ COMPLETED

Expand secrets rule library to 900+ detectors matching TruffleHog coverage (ACHIEVED: 938 rules). This includes: (1) Import existing Gitleaks/Checkov rule definitions, (2) Add AWS, GCP, Azure, GitHub, GitLab, Slack, Jira, Docker, JWT, and other cloud/service-specific patterns, (3) Add generic high-entropy patterns with configurable thresholds, (4) Add API key formats for 200+ services, (5) Add private key formats (RSA, EC, PGP, SSH), (6) Add database connection string patterns, (7) Implement heuristic context scoring to reduce false positives, (8) Add comprehensive tests with known secrets and non-secrets.

---

## Plugin Protocol Enhancement — Graph, Enrichment & Scan Context Primitives

Extend the plugin protocol with three new backward-compatible primitives required by Phase 7 features (AI triage, IaC cross-resource analysis, reachability analysis, K8s policy, taint tracking). All proto changes are additive (new fields/messages only) — old plugins and hosts remain fully compatible.

**Graph type**: Nodes + directed edges for relationship modeling. Supports NodeKind (resource, function, data, service, policy) and EdgeKind (depends_on, calls, flows_to, exposes, references). Domain types in core/graph/, proto messages in types.proto, fluent GraphBuilder in SDK.

**Enrichment type**: Annotates existing findings without modifying them, preserving determinism of the core scan engine. Links to findings via fingerprint, carries kind (triage, reachability, explanation), markdown body, metadata, confidence, and source plugin name. Domain type in core/findings/enrichment.go, fluent EnrichmentBuilder in SDK.

**ScanContext**: Carries core scan results (findings, packages, AI components) to post-scan plugins via InvokeToolRequest. Enabled by requires_scan_context=true on ToolDef. Host implements InvokePostScan() to orchestrate post-scan plugin invocation and merge results back.

**SDK extensions**: GraphBuilder and EnrichmentBuilder fluent APIs in sdk/response.go, ToolWithContext() in sdk/manifest.go for declaring post-scan tools, NodeKind/EdgeKind/Confidence constants in sdk/types.go, ToolRequest helper in sdk/request.go for accessing scan context.

**Conformance**: Extended validateResponse() in sdk/conformance.go to validate graph structure (node IDs, edge endpoint references) and enrichment fields. Track-specific options (WithRequireGraphs, WithRequireEnrichments) for track conformance testing.

**Bidirectional conversion**: Full proto↔domain conversion for Graph, Enrichment, ScanContext, NodeKind, EdgeKind in plugin/convert.go with roundtrip tests.

**Host extensions**: MergeResults() handles graphs and enrichments, estimateResponseSize() accounts for new types, InvokePostScan() orchestrates post-scan plugin lifecycle.

---

## Reachability Analysis Plugin

Language-specific call graph construction for Go, Python, and JavaScript/TypeScript to determine whether vulnerable dependency functions are actually called. Reduces false positives in dependency scanning by filtering unreachable code paths. Implemented as a plugin on the core-analysis track using the new Graph and Enrichment primitives. The plugin emits a call graph (function→function edges with EdgeKindCalls) and produces Enrichment annotations on dependency findings marking them as reachable or unreachable. Uses Go's go/callgraph for Go, tree-sitter for Python/JS/TS AST parsing. Requires scan context (findings + packages) from the core scan to know which dependency findings to evaluate.

---

## Graph-Based IaC Cross-Resource Analysis Plugin

Build a resource dependency graph from Terraform state/plan files and detect misconfigurations that span multiple resources (e.g., public subnet + no NACL + open security group, S3 bucket + no encryption + public ACL, RDS instance + public subnet + no encryption at rest). Implemented as a plugin on the core-analysis track. Emits Graph output with NodeKindResource nodes and EdgeKindDependsOn/EdgeKindReferences edges. Cross-resource rules are defined declaratively as graph patterns (subgraph matching). Extends existing tfplan.go resource parsing with a relationship model. Produces findings with precise multi-resource locations.

---

## Cross-File Taint Analysis Plugin

Dataflow tracking across function and file boundaries to detect untrusted input flowing to sensitive sinks (SQL queries, shell commands, eval, file operations, HTTP responses). Language-specific AST parsing for Go, Python, and JavaScript/TypeScript using tree-sitter grammars. Implemented as a plugin on the core-analysis track. Emits Graph output with NodeKindFunction/NodeKindData nodes and EdgeKindFlowsTo edges representing taint propagation paths. Produces findings with full taint path in the finding metadata (source→intermediate→sink). Taint sources: HTTP request params, environment variables, file reads, user input. Taint sinks: SQL, shell exec, eval, file write, HTTP response body.

---

## AI-Powered Triage Plugin

LLM-assisted severity adjustment and false-positive classification based on code context. Implemented as a post-scan plugin that consumes ScanContext (all findings from core scan) and produces Enrichment annotations with kind=triage. Each enrichment carries a verdict (true_positive, false_positive, needs_review), adjusted severity, confidence score, and markdown explanation. Integrates with the assist/ module's LLM provider abstraction. Opt-in only — never modifies original findings, only adds enrichments. Supports configurable LLM backends (OpenAI, Anthropic, Ollama for offline use). Includes historical pattern learning from user-confirmed triage decisions stored in .nox/triage-history.json. Planned on the agent-assistance track.

---

## Kubernetes Runtime Scanning Plugin

Live cluster scanning via kubectl/Kubernetes API access. Compares running workloads against IaC definitions for drift detection. Runtime-specific checks: containers running as root, mounted secrets in environment variables, missing network policies, privileged containers, host namespace sharing, missing resource limits, outdated images. Implemented as a plugin on the dynamic-runtime track with RiskActive safety class and needs_confirmation=true (since it accesses live infrastructure). Emits Graph output with NodeKindService/NodeKindResource nodes representing cluster topology. Produces findings for runtime misconfigurations and Enrichments linking runtime state to existing IaC findings (drift detection). Clearly marked as optional — breaks the offline-first constraint. Requires KUBECONFIG or in-cluster auth.

---

## Remediation plugin: deterministic code fixers with policy-driven blast-radius controls

Add a new remediation capability to nox via a dedicated plugin (`nox-plugin-remediate`) that extends dependency upgrades to safe, deterministic code issue remediation. Scope includes plugin tooling (`remediate.plan_code`, `remediate.apply_code`, `remediate.verify_code`), policy-driven risk and blast-radius controls (including auto-merge thresholds), and an initial phased backlog of five deterministic fixers with strict verification/rollback gates. Milestones: (0) plugin foundations and policy parser, (1) WEB-SEC-001 header middleware insertion, (2) AI-LOG-001 sensitive prompt/response log redaction, (3) SEC-003 hardcoded secret to env/config rewrite, (4) SEC-002 SQL parameterization codemods, (5) SEC-001 subprocess hardening codemods. Each fixer must meet acceptance criteria: deterministic output, idempotence, bounded change surface, golden fixtures, mandatory re-scan evidence, and rollback on verify failure.

---

## MCP Tool Poisoning Detection

Detect malicious instructions embedded in MCP tool metadata — the signature MCP attack (OWASP MCP03). Analyze tool descriptions, input schemas, and tool return values for: imperative injection phrases (e.g. 'ignore previous instructions', 'do not tell the user'), hidden/zero-width unicode, exfiltration verbs targeting secrets/files/credentials, and instructions that target the host model rather than the human operator. Reuses existing AI-PI prompt-injection heuristics. New rule IDs MCP-009..MCP-0xx in core/analyzers/ai. Closes the highest-signal gap vs Snyk Agent Scan and Aguara, both of which detect tool poisoning today while Nox only flags missing descriptions.

---

## MCP Rug Pull Detection

Detect post-install tool drift ('rug pull', OWASP MCP04). Hash MCP tool descriptions and schemas at first observation, persist to .nox/ state, and flag when a tool's definition changes after approval — the classic supply-chain trust-after-install attack. Reuses Nox's existing atomic-write content-hash state infrastructure (cache.go/state.go). Emits findings on drift with before/after hashes. Matches Snyk's 'tool pinning' and Aguara's rug-pull layer while staying fully offline and deterministic.

---

## MCP Authorization and Token Safety Rules

Close the MCP07 (insufficient authN/authZ) gap, anchored to the official MCP spec's normative MUST/SHOULD security clauses. New rules detecting: token passthrough (server accepting tokens not issued to it — explicitly forbidden), confused-deputy OAuth proxy patterns (static client ID + dynamic registration), SSRF during OAuth metadata discovery (cloud metadata 169.254.169.254, private IP ranges, DNS-rebinding/redirect chains), and session-id weaknesses (deterministic IDs, sessions-used-for-auth, missing user binding). Rules cite spec sections for defensibility.

---

## MCP Shadow Server and Allowlist Rules

Close the MCP09 (shadow/rogue server) gap. Detect MCP server configs lacking cryptographic identity verification, missing server allowlisting, and cross-server tool shadowing (a server redefining a tool name already provided by another, enabling override/escalation). Flag configs that trust unverified/unpinned remote servers. Static analysis over multi-client config inventory.

---

## OWASP MCP Top 10 Compliance Mapping

Map every MCP and AI rule to OWASP MCP Top 10 (MCP01-MCP10), the MCP-38 academic taxonomy, and the official MCP spec MUST/SHOULD clauses. Wire control IDs into core/compliance data and emit them as SARIF rule tags/properties so GitHub Code Scanning and registries see standards alignment. Table stakes for registry embedding and enterprise credibility — Aguara already maps to OWASP. Add a compliance framework entry 'owasp-mcp-top-10'.

---

## Multi-Client MCP Config Discovery

Expand discovery beyond mcp.json and claude_desktop_config.json to the 17+ MCP client config locations used by Cursor, VS Code, Windsurf, Cline, Continue, Gemini CLI, Zed, and others (platform-specific paths on macOS/Linux/Windows). Enables 'scan my whole machine for MCP servers' — the entry-point UX that Snyk Agent Scan and Aguara already provide. Pure discovery.go work plus a client-config registry. Price of entry for default-scanner status.

---

## Zero Telemetry Positioning and Guarantee

Weaponize the offline-first, no-telemetry, vendor-neutral wedge against the now-commercial Snyk Agent Scan (which phones home to Invariant's API and needs a Snyk token for some scans). Add an enforced offline guarantee: a test/CI gate asserting the scan path makes zero network calls, a --offline assertion, and prominent README/docs positioning ('The MCP scanner that never sees your code. No API. No token. No telemetry. Deterministic.'). The verifiable engineering parts (network-call assertion test, offline flag) are tracked here; messaging accompanies.

---

## MCP Distribution and Catalog Embedding

Win the embedding layer that makes a scanner 'default'. Dogfood Nox across the owner's own projects (Obvia, agent-go, Mnemos, Chronos, Praxis, statekit, Relicta) and publish findings as credibility content. Ship a one-command 'scan-before-publish' MCP workflow and GitHub Action variant focused on MCP servers. Pursue embedding in a trusted distribution layer (Docker MCP Catalog security tier or a downstream MCP registry's security check). Distribution/partnership track that converts capability into category ownership.

---

## MCP Rule Precision Hardening

Reduce false positives in the new MCP prose rules (MCP-009..014 tool poisoning, MCP-018/019 SSRF), surfaced by dogfooding nox against 17 of the owner's own MCP repos. The rules currently match defensive code, code comments, capability/permission descriptions, and test boilerplate rather than real tool metadata. Confirmed examples: MCP-018 fires on a repo's own SSRF blocklist (169.254.169.254 in a deny-list); MCP-014 fires on a test doc-comment 'after the first invocation'; MCP-009/011 fire on anti-injection system prompts and comments describing attacks. Needed: exclude test files (ignoreFilePatterns), avoid matching inside comments, suppress SSRF metadata hits in block/deny contexts, and anchor tool-poisoning prose to actual tool-description/string-literal context instead of free source text. Mirror the existing AI-028 fuzz-corpus FP-reduction approach. This is a gate before publishing any dogfood findings as launch content.

---

## Intelligence Console: full UI/UX review pass

A dedicated design pass over the NOX Intelligence operator console (nox-intelligence, internal/interfaces/httpapi/ui/index.html). The console has grown feature by feature — review queue, candidate detail, confirmations, sort/search, TOTP enrolment — and each addition was styled in isolation. The result works but has never been looked at as a whole.

WHY THIS NEEDS A SESSION RATHER THAN INCREMENTAL FIXES

Every UI defect found so far was found by looking at the rendered page, not by a test. None would have surfaced in CI. A list of the ones already fixed, because they show the pattern:

- `.linkish` lost a specificity contest to `.login button`, so "Back to sign in" and "Set one up" rendered as filled blue buttons competing with the primary action.
- The enrolment address field was read-only and empty for a signed-in operator, reading as a broken input.
- After a successful enrolment the emptied QR container survived as a small white box and a blank field under "Cannot scan it?" — reading as a failed image at the moment the operator needs to believe it worked.
- Opening a confirmation re-solved all six table columns under auto layout, so the whole table jumped sideways and moved other rows' buttons under the cursor — the exact misclick the confirmation exists to prevent.
- The evidence line read "5 nothing machine-checkable", a contradiction, because the count and its qualifier were concatenated without saying what the number counted.
- Search and sort shipped as markup with no listeners: the controls looked live and did nothing.

KNOWN OUTSTANDING ISSUES

- Margins and vertical rhythm are inconsistent between the review queue, the sign-in form and the enrolment panel. Spacing was set per-component with ad-hoc rem values rather than from a scale.
- The enrolment panel is tall enough that the QR pushes the confirm input below the fold on a 795px viewport; the operator scans, then has to hunt for where to type the code.
- Button hierarchy is flat. Generate, Confirm, sign out, "authenticator", escalate/reject and the linkish navigation all compete; only the destructive confirm has a distinct treatment.
- The dark theme is hardcoded. There is no light mode and no `prefers-color-scheme` handling, and the QR has to force a white ground because of it.
- The base config's dashboard provider points at a path that does not exist, logging a provisioning error on every start (cosmetic, but it is in the console's own logs).
- No responsive review below ~760px beyond the table's own scroll container.

SCOPE

Treat it as one design pass: establish a spacing scale and a button hierarchy, apply them across all views, then verify in the browser at several widths rather than trusting the tests. The existing ui_test.go guards structure (every called function is defined, the script boots, every id setReviewVisible hides exists, every input/select with an id is wired) — those catch wiring, not layout, and should stay as they are.

---

## Intelligence auth: regenerate recovery codes without re-enrolling

nox-intelligence v0.6.0 issues ten recovery codes when TOTP enrolment is confirmed, and that is the only place they are ever issued. GenerateRecoveryCodes has exactly one caller: confirmEnroll.

THE GAP

An operator who has spent most of their codes has no way to get more except by enrolling a new authenticator — which rotates the TOTP secret and invalidates the app they are still happily using. So the recovery mechanism forces a change to the primary factor, which is backwards: recovery exists to avoid disrupting the primary factor.

Every service that issues these (GitHub, GitLab, AWS, Stripe) exposes regeneration as its own action, precisely because running low is normal and re-enrolling is not.

WHAT IS NEEDED

- POST /v1/auth/recovery-codes — authorised by an existing session (the operator has already proven a factor) or by the operator token. Discards the old set and returns a new one, which GenerateRecoveryCodes already does atomically.
- Show the remaining count where the operator will see it. The service already computes it and returns it on a recovery-code sign-in; nothing surfaces it otherwise, so the first sign that codes are running out is running out.
- A console control alongside the existing "authenticator" button, and a CLI subcommand.

WHY IT IS NOT IN v0.6.0

Recovery codes were built to close the lockout that started this work, and issuing them at enrolment is the part that closes it. Regeneration is the follow-on that makes them sustainable rather than a one-shot. Splitting it keeps the security fix small and reviewable.

Current state, for whoever picks this up: the operator has 9 unused and 1 spent. The storage, hashing and single-use consumption are all in place and tested — this is an endpoint, a button and a subcommand over machinery that already exists.

## Deliver enrolment invitations by email

Enrolment invitations for the intelligence service are currently hand-carried: an operator registers someone, the console prints a single-use link, and a human copies it into a chat message. That works for a handful of operators and does not scale past it — and every hand-off is an opportunity to paste a credential somewhere it persists.

Deliver the invitation to the address it was issued for instead. The address is already known server-side (it is the subject of the binding code), so the invitation never needs to pass through the inviter's hands at all. That also closes the confused-deputy shape of the current flow, where the person who creates an account also holds the credential that activates it.

Scope: send on register, on re-invite, and on sign-up approval. Deliberately NOT in scope: general transactional email, notifications, or digests.

Constraints that fall out of what already exists:
- The link is single-use and expires in 24h (auth-go MagicLinkService, EnrolmentCodeTTL). Mail delivery must not lengthen that window to compensate for slow mailboxes.
- The service must not become undeliverable-silent: a send failure has to surface to the operator who triggered it, because an invitation nobody receives looks identical to one nobody has acted on yet. The console already handles the "registered but no link could be issued" case; this needs the same treatment.
- Resend is already the provider elsewhere in this fleet (alertmanager-resend-smtp in observability, vorhut-email), so the sender configuration is a solved problem to reuse rather than re-decide.
- nox-intelligence is a private service; the sender identity should be its own, not borrowed from another product.

Tracked upstream as nox-intelligence issue #4.

---

## Adjudicated conflict becomes INCONCLUSIVE (C3)

Track C3 of the evidence-native programme (docs/design/evidence-native-nox.md §2.4). The kernel already implements most of C3's conflict semantics: within a subject, stronger evidence wins, deterministic evidence cannot be overturned by a weaker heuristic, and equally strong contradictory claims are detectable via Ledger.Conflict. What is missing is the last step. core/adjudicate reports Verdict.Conflicted=true but still returns Exploitability=POTENTIAL, because DeriveExploitability is fed an empty RunOutcome and a scan executes nothing. The plan asks for equal contradictory strength to surface as INCONCLUSIVE, which is the state the kernel already defines as "executed, but the evidence was insufficient to decide". Resolving this needs a decision the code cannot make for itself: INCONCLUSIVE is currently reachable only after execution, so either the adjudicator derives exploitability differently for the static case, or the kernel gains a way to express "undecided without execution". Whichever is chosen, a conflict that collapses silently to POTENTIAL is a disagreement between two producers that the operator never sees, which is the thing conflict semantics exist to surface. Small and well-defined; the hard part is the choice, not the code.

---

## Fingerprint and waiver compatibility before the adjudication flip (C4)

Track C4 of the evidence-native programme (docs/design/evidence-native-nox.md §2.4), and the gate on C5. Nothing currently asserts that adjudication cannot change a fingerprint. That matters because fingerprints key baselines, VEX statements and nox:ignore comments across every consuming repository, so an output flip that moves them un-waives findings that were accepted and turns gates red in repos that changed nothing. This is not hypothetical: RetiredRuleIDs and AliasFingerprints exist in core/findings precisely because retiring one duplicate rule ID already did this once, at much smaller scale. Needed: a test asserting that every baseline entry and VEX statement valid before the flip is still valid after it; and if a fingerprint must move, the same alias mechanism and a migration note in the shape of docs/migration-fingerprint-v2.md. C5 must not ship without this. Recorded as a separate feature rather than a checklist item inside C5 because it is the dependency most likely to be skipped under time pressure, and the consequence lands in other people's repositories rather than this one.

---

## Finding becomes an adjudicated output (C5)

Track C5 of the evidence-native programme (docs/design/evidence-native-nox.md §2.4). The flip: Finding stops carrying an analyzer-authored verdict and becomes the output of adjudication. Analyzer Confidence becomes an INPUT to the adjudicator rather than the authority, and Severity keeps its own meaning — potential consequence if true — and is deliberately not merged into confidence. Ships as nox v2.0.0. Gated on C4 (fingerprint and waiver compatibility) and on Gate A, which already exists. The measurement C5 needed also exists: on the precision suite 15 of 37 findings diverge between analyzer confidence and what the evidence supports, every one of them the analyzer claiming more. Read that carefully — it is not evidence that the analyzers are wrong, it is the gap between what nox knows and what nox can currently record as evidence, and core/adjudicate carries the full reasoning in a doc comment. Retiring analyzer-authored confidence because evidence "should" be better would be a bet; retiring it having counted where the two disagree and in which direction is a decision.

---

## Intel as an evidence network (H)

Track H of the evidence-native programme (docs/design/evidence-native-nox.md §2.7). The intelligence service participates in adjudication using the SAME proposition and evidence semantics as local nox, not a parallel model: a research maturity ladder so a zero-day can benefit users before publication without pretending to certainty it does not have; independence and Sybil semantics that do not overstate a reporter count; retraction and supersession so knowledge can change. Local adjudication stays sovereign — if Intel disappears, nox still scans, still reasons locally, and reports the missing capability through the analysis-capability registry rather than going quiet. Gate C's preconditions are now all in place: the plan named producer authority (B5) and retraction (B4) as the two outstanding, and both landed in nox-core v0.2.0. Two things already established and worth not relitigating: the service's PUBLIC transition is correctly guarded on human approval plus corroboration from two distinct reporters, and its reporter identities are SELF-ASSERTED on the anonymous contribution endpoint — so a reporter count is a triage signal, not a measurement of independent belief, and CorroborationIsAttested exists to show that to the person taking the accountable act.

---

## Deterministic re-adjudication and explanation (I)

Track I of the evidence-native programme (docs/design/evidence-native-nox.md §2.7). Persist an evidence-rich scan artifact — input identity, capability state, claims, provenance, relationships, adjudication result — and make re-adjudication deterministic before attempting full scan reproducibility: same ledger plus same adjudicator version equals same verdict. That first half is far more achievable than replaying a whole repository scan and arguably more useful, and the groundwork is done: the reasoning store is already out-of-band and keyed by subject, the subject is derived from the finding rather than stored, and the evidence kernel is pure with caller-supplied timestamps so no verdict depends on a clock. The second half is explanation: every finding answers what was observed, why it matters, what supports it, what argues against it, WHAT WAS NOT EVALUATED, the potential impact, whether it affects this application, and what to do. Most of those answers already exist somewhere — claims, relations, capability gaps, the applicability ladder — and are not yet assembled into one thing a person reads. This is the cheapest of the remaining large tracks because it changes no scan output.

---

## Migrate the rule families to evidence-native (J)

Track J of the evidence-native programme (docs/design/evidence-native-nox.md §2.7), and by far the largest: roughly 1,600 distinct rule IDs across core/analyzers (~914 SEC, ~500 IAC, ~50 AI, ~21 MCP, ~12 DATA, plus VULN and SLOP). Migrate by value and risk, not alphabetically — noisy AI rules, secrets, endpoint/API misuse, taint overlaps, dependency applicability — and for each family answer five questions: what is the initial observation, what confirms it, what refutes it, what capability is required, what stays unknown. The plugin contract evolves toward specialised evidence producers (capability declaration, observations, claims, refutations, graph contribution, honest degradation) rather than independent security judges; core still allows genuine detector plugins. Analyzer-authored confidence is retired only once migration is far enough along, rather than maintaining two epistemic systems indefinitely. Ends with the Phase 11 benchmark suite measuring results rather than feature checkboxes: accuracy including a refutation false-negative rate, determinism, transparency, per-stage performance, and resilience when Intel, OSV or a plugin is unavailable. Explicit non-goals carried from the plan: do not replace all regex, do not move all plugins into core, do not add AI adjudication, do not maximise vulnerability count.

---

## API-ABUSE-001 sits at precision 0.000

Measured, not inferred (docs/benchmarks/2026-Q3/README.md). On testdata/precision-suite the api-abuse plugin's API-ABUSE-001 fires 17 times on 0.2.2 and 10 times on 0.2.3, with ZERO true positives in either version. Its precision is 0.000 — it has never once scored a true positive on this corpus. API-ABUSE-002 adds one more false positive in both versions. Two things follow. First, a correction to the record: the spec previously stated of the #28 fix that "its corpus FPs went 17 -> 0", and that is not what 0.2.3 measures; the fix roughly halved the noise rather than removing it. Second, api-abuse is the only plugin still emitting findings into scoring — threat-enrich and triage-agent became enrichment-only in 0.3.0 and contribute zero — so it alone accounts for the gap between core-only precision of 1.000 and 0.771 with the full plugin set. A rule that is not detecting anything is not a detector, and under the target architecture it would be a candidate generator whose output has to survive refutation before it becomes a finding. Re-measure rather than re-describe; a first-order candidate for Track J.

---

## isBareProviderPrefix is unreachable by any input

One of the six refiners in the secrets analyzer's refinement loop cannot be triggered. isBareProviderPrefix drops a match whose span is ONLY a provider prefix with no token body — the shape a pattern-vocabulary file has when it names the prefixes its rules detect. But no rule produces such a match: provider patterns require a token body, so a bare AKIA or a quoted "glpat-" matches nothing and the refiner never sees a candidate to refute. Established by probing, not by reading: several input shapes were tried across Go, Python, YAML and Markdown and none produced a raw match the refiner could act on. Recorded honestly in core/analyzers/secrets/reasoning_test.go, which covers the other five refiners end to end and states plainly that this one is NOT claimed as tested, because a test asserting a drop that cannot happen proves nothing. Either the refiner is dead code and should go, or the rules changed under it and the case it was written for now needs a different guard. Worth deciding rather than leaving as a permanent asterisk. Note the neighbouring precedent: TestScan_DataURIPayloadIsNotASecret was vacuous in exactly this way — it asserted "no findings" on input no rule ever matched, and passed identically with the filter it guarded deleted.

---

## Deduplication does not record which finding it dropped

The last silent drop in the scan pipeline. Track F named the dataflow, so a merge no longer loses what was merged: every candidate describing a flow is related to that flow BEFORE DeduplicateFlows runs, and the relation survives the collapse. What is still unrecorded is which specific finding was the one discarded, and on what basis — preferFlowFinding chooses by sink anchor, then line, then fingerprint, and none of that reasoning is written down. Deliberately left out of the config-removal work because a merge is not a refutation: Deduplicate, DeduplicateFlows and SuppressDuplicateVulnClass assert that two findings describe ONE condition, and recording that as either polarity would be wrong — a refutation claims evidence against a proposition, and a merge claims nothing about whether either finding is true. The right shape is probably evidence.StatusSuperseded, whose kernel definition already fits: "a later claim about the same subject replaces this one as the current reading; the superseded claim was not wrong, it is simply no longer the answer." Smaller than it was, and worth closing so that every drop in the pipeline has a recorded reason.

---

## Adopt policy.require_capabilities so Track D stops being inert

D5 shipped the gate that closes Track D's exit criterion — uninstalling or breaking an analyzer can no longer make a build greener — and nothing is using it. policy.require_capabilities is empty in every repository, which is by design: failing whenever anything is unevaluated would turn every build red on upgrade, since three analysis capabilities (constant evaluation, call graph, entry point) have no implementation at all, and a gate everybody disables within the hour protects nothing. So the mechanism is opt-in and currently protects no one. The work is adoption, not code: decide which capabilities this project's triage actually depends on, list them, and choose between uncertainty warn and fail. nox's own .nox.yaml is the obvious first adopter and the honest test of whether the setting is usable. Note the ordering the design doc asks for: warn first, for a release in which the warning names the flag, before fail becomes anyone's default — so that switching it later surprises nobody. Run nox analysis-capabilities to see what this installation can and cannot establish.

---
