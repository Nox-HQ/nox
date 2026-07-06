#!/usr/bin/perl
# SSRF: a request-controlled URL reaches an LWP::UserAgent fetch, letting an
# attacker drive server-side requests to arbitrary hosts — CWE-918. A correct
# scanner fires TAINT-006.
use strict;
use warnings;
use LWP::UserAgent;

sub fetch {
    my $ua  = LWP::UserAgent->new;
    my $url = $ENV{TARGET_URL};
    my $res = $ua->get($url); # nox-expect: TAINT-006
    return $res->content;
}

1;
