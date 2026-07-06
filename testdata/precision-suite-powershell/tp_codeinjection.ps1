# Code injection: an attacker-controlled argument flows into Invoke-Expression,
# which evaluates its string argument as PowerShell code. This is CWE-95, the
# canonical PowerShell code-injection sink. A correct scanner fires TAINT-005.
param(
    [string]$Formula
)

# The user supplies an expression that is evaluated verbatim — the vulnerability.
$expr = $Formula
Invoke-Expression $expr  # nox-expect: TAINT-005
