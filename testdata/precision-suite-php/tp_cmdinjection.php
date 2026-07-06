<?php
// Command injection: an attacker-controlled query parameter flows into a shell
// invocation via system() with no escaping. This is CWE-78. A correct scanner
// fires TAINT-002.

function runReport()
{
    $name = $_GET['report'];
    system("generate-report " . $name); // nox-expect: TAINT-002
}
