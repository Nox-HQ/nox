# Regression test for SPLATTING, which this suite's README and the extractor
# comment both documented as an open limit. It is not: a hashtable assigned from
# a source is tainted and carries into the splatted call.
#
# Pinned here so the stale claim cannot return. A documented gap that does not
# exist is the same defect as an unguarded one, in the other direction.
$params = @{ Uri = $args[0] }
Invoke-WebRequest @params  # nox-expect: TAINT-006
