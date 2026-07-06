<?php
// Path traversal / local file disclosure: a request parameter is passed to
// readfile() unchecked, so `?file=../../etc/passwd` escapes the intended
// directory. CWE-22, TAINT-004.

function download()
{
    $file = $_GET['file'];
    readfile("/var/www/files/" . $file); // nox-expect: TAINT-004
}
