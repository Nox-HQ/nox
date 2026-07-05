import yaml  # nox-expect: SLOP-001
def load(untrusted):
    return yaml.load(untrusted)  # nox-expect: VARIANT-002
