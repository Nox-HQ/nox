# Clean: the untrusted action is validated against a strict allow-pattern with
# -match, and only a FIXED, allow-listed command is ever executed — the tainted
# value never reaches the sink. This models the "validate then run a known-safe
# operation" pattern. A finding here is a false positive.
#
# NOTE (honest): nox does not model -match as a sanitizer that launders the
# tainted variable itself; this sample is clean because the sink argument is a
# constant, not because the -match reclassifies $action. A sample that fed the
# validated $action straight into a sink would (correctly) still fire — validation
# by regex is not the same as neutralization.
param(
    [string]$Action
)

$action = $Action
if ($action -match '^(start|stop|status)$') {
    # Run the fixed service verb, never the raw input.
    $verb = "Restart-Service"
    & $verb -Name "Spooler"
}
