<?php
// Local file inclusion: a request parameter drives a dynamic include(), so an
// attacker controls which PHP file executes (LFI/RFI). CWE-22, TAINT-004.

function route()
{
    $page = $_GET['page'];
    include($page . ".php"); // nox-expect: TAINT-004
}
