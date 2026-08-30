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
# The literals here are synthetic and match no issued credential. The GitHub
# token nonetheless carries a VALID embedded CRC32 checksum, and that is
# deliberate: it was replaced once checksum verification landed, because the
# original had a random body and would have been refuted deterministically.
#
# A sample that a refiner can correctly dismiss does not guard against anything.
# The point of this case is a credential no OFFLINE check can distinguish from a
# real one, so every offline check has to pass — including the one that did not
# exist when the sample was written.
EXAMPLE_PLACEHOLDER_TOKEN = "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"  # nox-expect: SEC-003
SAMPLE_AWS_KEY = "AKIA2E4MQJ7XTBUNDXYZ"  # nox-expect: SEC-001 SEC-508
