<?php
// Safe input-handling idioms across classes — each user value passes through the
// correct sanitizer for its sink before use, so nothing should fire.

// XSS defused by htmlspecialchars before echo.
function greet()
{
    $raw = $_GET['name'];
    $name = htmlspecialchars($raw, ENT_QUOTES, 'UTF-8');
    echo "<h1>Hello, " . $name . "</h1>";
}

// Command injection defused by escapeshellarg.
function ping()
{
    $raw = $_GET['host'];
    $host = escapeshellarg($raw);
    system("ping -c 1 " . $host);
}

// Path traversal defused by basename (strips directory components).
function download()
{
    $raw = $_GET['file'];
    $file = basename($raw);
    readfile("/var/www/files/" . $file);
}
