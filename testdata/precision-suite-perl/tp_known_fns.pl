#!/usr/bin/perl
# Two flows that were honest false negatives until container binding and the
# cross-sub shared-state join landed; they are kept as the regression tests for
# those shapes. See README.md "Closed gaps".
use strict;
use warnings;

# Hash-element laundering: the assignment target is a subscripted lvalue, not a
# bare scalar. The CONTAINER is now bound, so a taint on any element taints every
# read of it — field-insensitive, which can only widen taint.
sub launder_hash {
    my %args;
    $args{cmd} = $ENV{CMD};
    system("run $args{cmd}"); # nox-expect: TAINT-002
}

# Cross-subroutine flow through a package global. The binding of an `our` name is
# now copied into every other unit that reads it. Only `our` globals join; a `my`
# lexical never does.
our $PAYLOAD;

sub stash {
    $PAYLOAD = $ENV{DATA};
}

sub flush {
    system("logger $PAYLOAD"); # nox-expect: TAINT-002
}

1;
