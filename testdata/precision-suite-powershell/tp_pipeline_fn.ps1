# Pipeline dataflow (CWE-95 code injection): the tainted value is piped into
# Invoke-Expression rather than passed as a positional argument. `$x | Cmdlet`
# binds $x to the cmdlet's pipeline input, which is a real argument position —
# this executes $x exactly as `Invoke-Expression $x` would. The recognizer splits
# the line at every top-level `|` and folds the stages left into nested calls, so
# the value reaches the final stage. Was a documented false negative until that
# landed; kept as the regression test for it.
$payload = $args[0]
$payload | Invoke-Expression  # nox-expect: TAINT-005
