<?php
// Safe database idioms — every one is the correct, guarded form, so a precise
// scanner fires nothing. Zero findings expected.

// A prepared statement with a bound placeholder: the driver binds the value, so
// no injection is possible. The tainted value never touches the SQL string.
function findUser($pdo)
{
    $id = $_GET['id'];
    $stmt = $pdo->prepare("SELECT name, email FROM users WHERE id = :id");
    $stmt->execute([':id' => $id]);
    return $stmt->fetch();
}

// Numeric coercion via intval removes every injection metacharacter before the
// value reaches the query.
function findByPage($conn)
{
    $raw = $_GET['page'];
    $page = intval($raw);
    return mysqli_query($conn, "SELECT * FROM posts LIMIT " . $page);
}
