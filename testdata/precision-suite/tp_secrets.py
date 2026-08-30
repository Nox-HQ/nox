# The GitHub token carries a VALID embedded CRC32 checksum. It was replaced
# when checksum verification landed: the previous literal had a random body,
# so a checksum-aware scanner could deterministically establish it was not a
# GitHub credential — and a sample a correct scanner can refute is a poor
# true positive for "a hardcoded GitHub token".
#
# Synthetic and matching no issued credential; the body says so in plain text.
AWS_KEY = "AKIAIOSFODNN7EXAMPLE"  # nox-expect: SEC-001 SEC-508
GITHUB_TOKEN = "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"  # nox-expect: SEC-003
SLACK_TOKEN = "xoxb-1234567890-1234567890123-AbCdEfGhIjKlMnOpQrStUvWx"  # nox-expect: SEC-023
