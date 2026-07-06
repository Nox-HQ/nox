<?php
// Placeholder / example credentials and config reads — none is a real secret and
// none is a live taint flow, so a precise scanner fires nothing.

// Example placeholders, the kind that ship in a config template.
$dbPassword = 'your-db-password-here';
$apiKey     = 'changeme';
$dsn        = 'mysql://USER:PASSWORD@localhost:3306/app';
$stripeTest = 'sk_test_00000000000000000000000000';

// Reading configuration from the environment is not an injection source in this
// model; a constant command with no user input is safe.
$logDir = getenv('APP_LOG_DIR');
system('logrotate /etc/logrotate.conf');

echo "config loaded";
