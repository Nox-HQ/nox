#!/usr/bin/perl
# Command injection: a request/environment-controlled value flows into a shell
# command with no escaping — CWE-78. A correct scanner fires TAINT-002 on each
# dangerous call. Covers the three idioms a Perl line-recognizer must handle: a
# paren-less `system`, a backtick command literal, and an explicit `exec`.
use strict;
use warnings;

# Paren-less system with interpolation — classic RCE.
sub ping {
    my $host = $ENV{REMOTE_HOST};
    system "ping -c 1 $host"; # nox-expect: TAINT-002
}

# Backtick command execution — the command literal has no ordinary call syntax
# but is a command-injection sink all the same.
sub traceroute {
    my $target = $ENV{TARGET};
    my $output = `traceroute $target`; # nox-expect: TAINT-002
    return $output;
}

# Explicit exec with a tainted command string.
sub restart {
    my $svc = $ARGV[0];
    exec("systemctl restart $svc"); # nox-expect: TAINT-002
}

1;
