# Path traversal: an untrusted file name is read directly with Get-Content, so a
# value like "..\..\Windows\System32\config\SAM" escapes the intended directory.
# CWE-22. A correct scanner fires TAINT-004. The safe form strips the directory
# with Split-Path -Leaf (see clean_safe_path.ps1).
param(
    [string]$FileName
)

$path = $FileName
Get-Content -Path $path  # nox-expect: TAINT-004
