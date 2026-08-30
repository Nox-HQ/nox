# Guards: value-semantics refutation (Track E3).
#
# ENRICH-004 matched the NAME of an assignment (`api_key = "`) and never looked
# at the value, so every documentation placeholder scored as a hardcoded
# secret. E3 fixes that by reading the literal. The corpus already pins the
# positive half of that fix: clean_placeholders.py must stay silent.
#
# This is the negative half. Both credentials below carry live provider
# formats — a GitHub PAT prefix and an AWS access key ID, each with a
# well-formed body — and both are bound to identifiers that say, as loudly as
# an identifier can, that they are examples. A refuter that reads the name, or
# that treats "example"/"sample" anywhere nearby as a placeholder signal, drops
# two real credentials. The value is the evidence; the name is not.
#
# The literals here are synthetic and match no issued credential.
EXAMPLE_PLACEHOLDER_TOKEN = "ghp_7Kd2mQ9xR4tB1nZ6wY3vC8hL5jF0gS2pA9eU"  # nox-expect: SEC-003
SAMPLE_AWS_KEY = "AKIA2E4MQJ7XTBUNDXYZ"  # nox-expect: SEC-001 SEC-508
