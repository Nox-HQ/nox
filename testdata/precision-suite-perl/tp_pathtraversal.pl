#!/usr/bin/perl
# Path traversal: a request-controlled filename reaches open() with no
# canonicalization — CWE-22. A correct scanner fires TAINT-004. The safe form
# (File::Basename::basename strips directory components) lives in clean_safe_db.pl
# and must NOT fire.
use strict;
use warnings;

sub download {
    my $name = $ENV{FILE};
    open(my $fh, "<", $name); # nox-expect: TAINT-004
    my @lines = <$fh>;
    close($fh);
    return join("", @lines);
}

1;
