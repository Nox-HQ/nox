# Command injection: a user-supplied program name is invoked through the call
# operator (&), which runs whatever command the string names. A tainted command
# name is CWE-78. A correct scanner fires TAINT-002. nox models `& $cmd` as the
# synthetic InvokeOperator sink and sees the tainted $tool flow into it.
param(
    [string]$Tool
)

$tool = $Tool
& $tool --report  # nox-expect: TAINT-002
