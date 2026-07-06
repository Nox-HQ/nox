#!/usr/bin/perl
# Clean: the SAFE counterparts of every tp_*.pl flow. None of these should fire —
# each routes the tainted value through the sanitizer / parameterized form that
# neutralizes its sink's vuln class. A finding on any line here is a false
# positive.
use strict;
use warnings;
use DBI;
use File::Basename qw(basename);

# Parameterized DBI: the tainted value is a bind parameter (passed to `do` after
# the SQL string), not interpolated into it — safe against SQL injection.
sub by_user {
    my ($dbh) = @_;
    my $id = $ENV{USER_ID};
    $dbh->do("SELECT * FROM users WHERE id = ?", undef, $id);
}

# Prepared statement with a placeholder, then bind via execute — safe.
sub lookup_name {
    my ($dbh) = @_;
    my $name = $ENV{NAME};
    my $sth  = $dbh->prepare("SELECT * FROM users WHERE name = ?");
    $sth->execute($name);
}

# Integer coercion strips every injection metacharacter before the shell command.
sub ping {
    my $raw   = $ENV{COUNT};
    my $count = int($raw);
    system "ping -c $count example.com";
}

# quotemeta escapes shell metacharacters before the command runs.
sub lookup_host {
    my $host = $ENV{HOST};
    my $safe = quotemeta($host);
    system "host $safe";
}

# File::Basename::basename strips directory components, defusing path traversal.
sub download {
    my $name = $ENV{FILE};
    my $base = basename($name);
    open(my $fh, "<", "/srv/downloads/$base");
    return <$fh>;
}

# No source: a constant command is never tainted.
sub status {
    system "systemctl status nginx";
}

1;
