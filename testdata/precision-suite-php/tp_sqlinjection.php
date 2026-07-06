<?php
// SQL injection: a user-supplied id is concatenated into a query string and run
// through a PDO method call ($pdo->query) — no prepared statement, no binding.
// This is CWE-89. A correct scanner fires TAINT-001.

function findUser($pdo)
{
    $id = $_GET['id'];
    $sql = "SELECT name, email FROM users WHERE id = " . $id;
    return $pdo->query($sql); // nox-expect: TAINT-001
}
