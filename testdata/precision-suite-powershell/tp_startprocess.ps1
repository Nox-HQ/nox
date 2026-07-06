# Command injection: an untrusted value from an environment variable is passed
# as the file/arguments of Start-Process, launching an attacker-controlled
# process. CWE-78. A correct scanner fires TAINT-002.
$payload = $env:DEPLOY_CMD
Start-Process -FilePath "cmd.exe" -ArgumentList "/c $payload"  # nox-expect: TAINT-002
