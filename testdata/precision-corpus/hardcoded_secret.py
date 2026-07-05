# True-positive sample: a hardcoded AWS access key id. The scan MUST
# flag the credential line below. The `nox-expect` annotation names every
# rule that legitimately fires on that line — one credential trips two
# overlapping AWS-key detectors, and that overlap is itself a precision
# signal worth measuring (a triager sees two findings for one secret).


def load_aws_client():
    access_key = "AKIAIOSFODNN7EXAMPLE"  # nox-expect: SEC-001 SEC-508
    return access_key
