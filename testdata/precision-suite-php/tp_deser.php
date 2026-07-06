<?php
// Unsafe deserialization: a cookie value is passed to unserialize(), enabling
// PHP object injection (POP-chain RCE) on untrusted input. CWE-502, TAINT-005.

function loadSession()
{
    $blob = $_COOKIE['session'];
    $state = unserialize($blob); // nox-expect: TAINT-005
    return $state;
}
