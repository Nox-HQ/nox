<?php
// Code injection: a POST field is passed to eval(), so an attacker runs
// arbitrary PHP. CWE-95, TAINT-005.

function compute()
{
    $formula = $_POST['formula'];
    eval("\$result = " . $formula . ";"); // nox-expect: TAINT-005
}
