<?php
// SQL injection via the procedural mysqli_query API: the request value is
// interpolated into the query with no escaping. CWE-89, TAINT-001.

function search($conn)
{
    $term = $_POST['q'];
    $query = "SELECT * FROM products WHERE name LIKE '%" . $term . "%'";
    return mysqli_query($conn, $query); // nox-expect: TAINT-001
}
