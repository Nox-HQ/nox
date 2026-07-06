# Clean: placeholder / example credentials and an environment-variable lookup for
# the real secret. None of these are live secrets, and there is no source→sink
# flow. Any secret or taint finding here is a false positive.

# Example values a user is expected to replace — not real credentials.
$ApiKey       = "your-api-key-here"
$DbPassword   = "<set-me-in-ci>"
$ExampleToken = "xxxxxxxxxxxxxxxxxxxxxxxx"

# The real secret comes from the environment at run time, never hard-coded.
$RealKey = $env:SERVICE_API_KEY

Write-Host "Configured API client (key length: $($RealKey.Length))"
