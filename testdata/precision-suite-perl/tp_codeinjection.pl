#!/usr/bin/perl
# Code injection: a tainted value reaches Perl's string `eval`, executing
# arbitrary code — CWE-95. A correct scanner fires TAINT-005.
use strict;
use warnings;

sub run_expr {
    my $user = $ENV{EXPR};
    eval $user; # nox-expect: TAINT-005
}

1;
