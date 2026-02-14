# Secrets Rule Expansion Tasks

## Current State
- Nox: 160 secrets rules
- Gitleaks: 200+ secret patterns (ready to import)

## Import Priority

### P0: High-Impact Secrets (import first)
- AWS keys (already have SEC-001, SEC-002)
- GitHub tokens  
- GCP keys
- Azure secrets
- Private keys (RSA, EC, PGP)

### P1: Cloud & SaaS Providers
- Stripe, Twilio, SendGrid
- Slack, Discord, Atlassian
- Database connections (Redis, PostgreSQL, MySQL)

### P2: Import All Gitleaks Rules
- Remaining 100+ patterns from gitleaks.toml

## Target
- Reach 500+ secrets rules (match TruffleHog at ~900 detectors is long-term)
- Current 160 → Target: 500+
