# CI Remediation Bot Example

This example shows a lightweight Dependabot-like workflow using existing Nox commands.

It runs on a schedule and can also be triggered manually:

1. runs `nox scan`
2. generates a remediation plan with `nox fix --dry-run`
3. applies upgrades with `nox fix`
4. opens a PR with the resulting manifest/lockfile changes

## Notes

- This is repository-local automation, not a hosted SaaS bot.
- Auto-merge should be controlled by branch protection + policy checks.
- For blast-radius-aware auto-merge, see `docs/proposals/remediation-bot-plugin.md`.
