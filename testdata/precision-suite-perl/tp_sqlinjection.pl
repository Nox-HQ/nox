#!/usr/bin/perl
# SQL injection: a request parameter is interpolated straight into a DBI SQL
# string — CWE-89. A correct scanner fires TAINT-001. The safe, parameterized
# form (a `?` placeholder with the value as a bind arg) lives in clean_safe_db.pl
# and must NOT fire.
use strict;
use warnings;
use DBI;

sub by_user {
    my ($dbh) = @_;
    my $id = $ENV{USER_ID};
    $dbh->do("SELECT * FROM users WHERE id = $id"); # nox-expect: TAINT-001
}

sub lookup_name {
    my ($dbh) = @_;
    my $name = $ENV{NAME};
    my $sth = $dbh->prepare("SELECT * FROM users WHERE name = '$name'"); # nox-expect: TAINT-001
    $sth->execute();
}

1;
