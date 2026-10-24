# Nox — Vision

Nox is an open, language-agnostic security engine for modern software
systems, including AI-powered applications.

Its purpose is to provide deterministic, inspectable, and composable security
analysis that can be used by humans, CI systems, and AI agents alike.

Nox is not a SaaS platform, not a dashboard, and not a black box.
It is a security primitive.

## Core Principles

### Determinism

Given the same inputs, Nox must produce the same outputs.
No hidden state, no opaque heuristics, no non-versioned behavior.

### Auditability

All detection logic, rules, and mappings are inspectable and versioned.
Security findings must be explainable without proprietary context.

### Language Agnosticism

Nox analyzes artifacts, not programming languages:

- files
- configs
- dependencies
- containers
- AI system components

### Agent-Native

Nox is designed to be safely callable by AI agents via MCP,
with explicit sandboxing and read-only defaults.

### Safe by Default

Nox never:

- uploads source code by default
- executes untrusted code
- performs destructive actions
- auto-applies fixes without explicit opt-in

## What Nox Is Not

- A hosted security platform
- A SOC or SIEM tool
- A replacement for human security judgment
- An automatic remediation engine

## Long-Term Vision

The sections below are 15–18 of the product vision, *Nox — Product Vision,
Intent & Design Philosophy*. They set the direction; the principles above set
the constraints every step toward it must keep.

### The Long-Term Ambition

The long-term ambition is larger than static analysis, vulnerability scanning,
or security automation.

Nox should become the trusted security companion for everyone who builds
software.

As software creation becomes increasingly accessible through AI coding agents,
natural-language development environments, and automated engineering
workflows, security must become equally accessible.

It is unrealistic to expect every person building software to become
proficient in application security, dependency management, infrastructure
hardening, threat modeling, and vulnerability remediation.

Instead, the development environment itself must take on more of that
responsibility.

Nox should help make this possible.

A developer should be able to build an application, run Nox, and receive a
meaningful assessment of its security without first understanding the
underlying security disciplines.

As the application evolves, Nox should evolve its understanding alongside it.

- When a dependency becomes vulnerable, Nox should recognize the change.
- When a new API introduces an authorization risk, Nox should identify it.
- When an AI agent gains access to sensitive capabilities, Nox should evaluate
  the implications.
- When an infrastructure change invalidates a previously established security
  assumption, Nox should surface that change.
- When a fix is available, Nox should help prepare, apply where authorized, and
  verify the remediation.
- When an organization needs a threat model, security documentation, or
  compliance evidence, Nox should help produce those artifacts from its existing
  understanding of the system.

The developer should not have to coordinate a collection of disconnected
security products to accomplish these tasks.

Nox should provide one coherent security experience throughout the software
lifecycle.

#### From periodic scanning to continuous security understanding

The evolution of Nox can be understood in four stages.

**Stage 1 — Detect.** Nox identifies security risks through deterministic
analysis, vulnerability intelligence, and specialized security checks. The
experience resembles a conventional linter: run a command and receive
actionable findings.

**Stage 2 — Explain and remediate.** Nox explains findings in accessible
language, identifies practical fixes, prepares changes, and verifies
remediation outcomes. Security becomes less dependent on specialized
expertise.

**Stage 3 — Understand and anticipate.** Nox maintains an evidence-backed
understanding of the application's architecture, dependencies, trust
boundaries, and security assumptions. It recognizes when changes invalidate
earlier conclusions and recommends additional analysis when new risks emerge.

**Stage 4 — Continuously assist.** Nox becomes a persistent security capability
within the development lifecycle. It monitors relevant changes, coordinates
verification, helps maintain security controls, supports authorized
remediation, and produces reusable security evidence.

At every stage, the system must remain transparent about its capabilities and
limitations.

Increasing autonomy must not come at the expense of accountability or
correctness.

### The Product Philosophy in One Sentence

Nox makes security an automatic, trustworthy part of building software—just as
formatting, linting, and testing are today.

The product should allow people to focus on creating software while Nox
continuously helps them understand, improve, and maintain its security.

Its core experience should be simple enough for someone building their first
application and reliable enough to become part of a professional engineering
organization's development process.

The sophistication belongs inside the system.

The confidence belongs with the developer.

### The Ultimate User Experience

Imagine someone building a SaaS application with an AI coding agent.

They have implemented authentication, a database, several API endpoints,
payment processing, and an AI-powered feature.

They may not know how to perform a security review.

They should not need to.

They run:

```
nox scan .
```

Nox identifies the application's relevant technologies and security surfaces,
performs the applicable checks, and produces an understandable assessment.

For example:

```
Nox Security Assessment

Your application has been scanned.

2 issues need attention.
- A dependency contains a known vulnerability. A compatible update is available.
- One API endpoint may expose records without sufficient authorization checks.
Security checks completed: Secrets, dependencies, application security, infrastructure configuration, and AI integration checks.

Additional verification recommended: Runtime authorization testing for the affected endpoint.

Nox can prepare a dependency update and help investigate the authorization issue.
```

The user can then ask:

> Can you fix these?

Nox prepares the changes it can safely make and explains which actions require
review or additional information.

After the changes are applied, Nox reruns the relevant checks and reports what
was verified.

The developer connects Nox to their CI pipeline.

From then on, security checks become part of normal development.

Weeks later, a vulnerability is disclosed in one of the application's
dependencies.

NOX Intelligence identifies the advisory. Nox evaluates its relevance to the
application and, according to the configured policy, reports the issue,
prepares a fix, or initiates an approved remediation workflow.

Later, the developer asks:

> I'm preparing for ISO 27001. What can you help me with?

Nox uses the security evidence it has already collected, identifies relevant
technical controls, generates supporting artifacts, and explains what
additional organizational evidence is required.

At no point does the developer need to understand which internal analyzer,
intelligence component, or plugin performs each operation.

They simply interact with Nox.

This is the intended experience.

### Closing Principle

The purpose of Nox is not to eliminate the need for security expertise in
every circumstance.

Complex systems, high-risk applications, regulatory obligations, and
sophisticated threats will continue to require specialist judgment.

The purpose is to eliminate unnecessary security complexity from everyday
software development.

Most developers should not have to assemble security scanners, interpret
dozens of overlapping reports, track vulnerability databases, or manually
coordinate routine remediation.

Nox should take on as much of that work as can be performed reliably, safely,
and transparently.

The remaining uncertainty should be communicated clearly.

The necessary human decisions should be surfaced at the appropriate time.

And the system should become more useful as it gains evidence about the
application.

The ultimate goal is not for developers to believe that their software is
perfectly secure.

It is for developers to know that security is being taken care of
continuously, that important problems will be surfaced, and that Nox will help
them do something about those problems.

That is the trust Nox should earn.

That is the product we want to build.
