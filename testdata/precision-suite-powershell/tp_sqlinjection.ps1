# SQL injection: an untrusted id is string-interpolated straight into the query
# text passed to Invoke-Sqlcmd, with no parameterization. CWE-89. A correct
# scanner fires TAINT-001. The safe form binds the value with a @parameter (see
# clean_parameterized.ps1).
param(
    [string]$UserId
)

$id = $UserId
$query = "SELECT * FROM Users WHERE Id = $id"
Invoke-Sqlcmd -Query $query -ServerInstance "db01"  # nox-expect: TAINT-001
