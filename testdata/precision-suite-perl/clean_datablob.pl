#!/usr/bin/perl
# Clean: a data blob, not code. A long base64 / data-URI payload in a heredoc and
# a quote-like literal is exactly the noise broad pattern rules trip on. lexctx
# marks the heredoc body and q() literal as string data, so no taint or secret
# finding should fire here. A finding on any line is a false positive.
use strict;
use warnings;

# An embedded SVG icon as a data-URI base64 blob inside a nowdoc-style heredoc
# (single-quoted terminator: no interpolation). This is data, not a secret.
my $icon = <<'DATA';
data:image/svg+xml;base64,PHN2ZyB4bWxucz0iaHR0cDovL3d3dy53My5vcmcvMjAwMC9zdmci
IHZpZXdCb3g9IjAgMCAxNiAxNiI+PHBhdGggZD0iTTggMEwwIDhsOCA4IDgtOHoiLz48L3N2Zz4K
QUtJQTEyMzQ1Njc4OTBBQkNERUYxMjM0NTY3ODkwQUJBS0lBMTIzNDU2Nzg5MEFCQ0RFRg==
DATA

# A long minified/base64 config chunk assigned from a double-quoted literal —
# still data, not a secret. lexctx classifies it as a string blob (over the
# blob-length threshold) so pattern rules are suppressed.
my $blob = "eJzT0yMAAGTvBe8xNjQ1MDIyNjE1M7ewtLK2sbWzd3B0cnZxdXP38PTy9vH18/cIDAoOCQ0LDwiMio6JjYuPiExKTk";

print length($icon), "\n";
print length($blob), "\n";

1;
