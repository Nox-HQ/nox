#!/usr/bin/perl
# CGI source: the classic Perl web entry point. CGI's `param` returns
# attacker-controlled request data; here it flows into a shell command (CWE-78).
# Exercises both the object form `$q->param(...)` and the imported bare `param(...)`.
use strict;
use warnings;
use CGI;

sub handle_object {
    my $q    = CGI->new;
    my $host = $q->param('host');
    system("ping -c 1 $host"); # nox-expect: TAINT-002
}

sub handle_imported {
    my $file = param('name');
    open(my $fh, "<", $file); # nox-expect: TAINT-004
    return <$fh>;
}

1;
