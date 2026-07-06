<?php
// Reflected XSS: a request parameter is echoed straight into the HTML response
// with no output encoding, so an attacker's markup/script executes in the
// victim's browser. CWE-79, TAINT-003.

function greet()
{
    $name = $_GET['name'];
    echo "<h1>Hello, " . $name . "</h1>"; // nox-expect: TAINT-003
}
