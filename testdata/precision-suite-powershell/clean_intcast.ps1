# Clean: the untrusted value is coerced to an integer with a [int] cast before it
# is used to build a process argument. Numeric coercion removes every injection
# metacharacter, so no command injection is possible even though the value is
# interpolated. A TAINT-002 finding here is a false positive.
param(
    [string]$Count
)

$raw = $Count
$n = [int]$raw
Start-Process -FilePath "worker.exe" -ArgumentList "--jobs $n"
