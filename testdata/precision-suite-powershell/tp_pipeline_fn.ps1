# Honest FALSE NEGATIVE (documented): the tainted value is piped into
# Invoke-Expression rather than passed as a positional argument. This is a real
# CWE-95 code injection — a correct scanner SHOULD fire TAINT-005 — but nox's
# flat line/statement recognizer does not model PowerShell pipeline dataflow
# (`$x | Cmdlet` binds $x to the cmdlet's pipeline input, which the recognizer
# does not track). The annotation below therefore scores as a recall gap, which
# is exactly the point of the honest suite: PowerShell recall is moderate and the
# number must show it. See README.md "What this corpus reveals".
$payload = $args[0]
$payload | Invoke-Expression  # nox-expect: TAINT-005
