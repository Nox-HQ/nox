#!/usr/bin/perl
# Honest false negatives: real flows a *correct* scanner should flag that nox's
# pragmatic Perl line-recognizer does NOT. They are annotated so they score as
# recall (a number below 1.0), never as silence. Samples are never edited to fake
# the score — the engine is built to catch what it honestly can, and the rest is
# recorded here. See README.md "Known gaps". Neither line below produces ANY
# finding, so each scores purely as a missed true positive (recall), never a
# false positive.
use strict;
use warnings;

# GAP 1 — taint laundered through a hash element. The tainted value is stored in
# $args{cmd}, but the assignment target is a subscripted lvalue, not a bare
# scalar. nox's engine tracks simple-identifier assignments only (no container /
# element sensitivity — the documented Python/JS/Ruby limit), so the taint is
# lost at the hash store and the sink read of $args{cmd} looks clean.
sub launder_hash {
    my %args;
    $args{cmd} = $ENV{CMD};
    system("run $args{cmd}"); # nox-expect: TAINT-002
}

# GAP 2 — cross-subroutine flow through a package global. The source lands in
# our $PAYLOAD in one sub and is read by a sink in another. nox's same-file
# interprocedural pass tracks LOCAL HELPER CALLS via function summaries, not
# shared package/global state, so a value laundered across two subs through a
# global is not joined. This is the documented boundary of the intraprocedural +
# local-summary model, not a Perl-specific defect.
our $PAYLOAD;

sub stash {
    $PAYLOAD = $ENV{DATA};
}

sub flush {
    system("logger $PAYLOAD"); # nox-expect: TAINT-002
}

1;
