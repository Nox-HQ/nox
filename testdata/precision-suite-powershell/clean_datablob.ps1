# Clean: a here-string carrying a long base64 data-URI blob (an embedded icon).
# The long alphanumeric run inside is data, not a secret, and the here-string is
# never used as a command/path/query. Any secret or taint finding here is a false
# positive — the lexctx here-string classifier marks the body as a data blob.
$IconDataUri = @'
data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCCAKIA1234567890ABCDEF1234567890ABAKIA1234567890ABCDEF1234567890AB
'@

# A non-interpolating literal here-string: even a $(dangerous) inside is inert data.
$Template = @'
Report generated for $(placeholder) — do not evaluate.
'@

Write-Output $IconDataUri.Length
Write-Output $Template.Length
