# Clean: the untrusted id is bound as a @parameter via
# SqlCommand.Parameters.AddWithValue, so it is passed to the driver as data and
# never concatenated into the SQL text. The CommandText is a constant with a
# @id placeholder. No SQLi is possible; a TAINT-001 finding here is a false
# positive.
param(
    [string]$UserId
)

$id = $UserId
$cmd = New-Object System.Data.SqlClient.SqlCommand
$cmd.CommandText = "SELECT * FROM Users WHERE Id = @id"
$cmd.Parameters.AddWithValue("@id", $id)
$reader = $cmd.ExecuteReader()
