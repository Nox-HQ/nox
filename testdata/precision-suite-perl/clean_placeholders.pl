#!/usr/bin/perl
# Clean: placeholder / example configuration, not a live flow. These are the
# `.env.example`-style stand-ins and public checksums that broad rules flag as
# secrets or taint. None reaches a sink; a finding on any line is a false positive.
use strict;
use warnings;

# Example credentials in POD documentation — prose, never executed.

=head1 CONFIGURATION

Set these before running:

    export API_TOKEN=your-token-here
    export DB_PASSWORD=changeme

=cut

# Placeholder constants — obvious non-secrets, and never tainted.
my $api_token   = "your-api-token-here";
my $db_password = "changeme";

# A public content checksum (a git blob SHA) — not a credential.
my $schema_sha = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4";

print "configured\n";

1;
