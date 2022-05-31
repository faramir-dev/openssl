#! /usr/bin/env perl
# Copyright 2022 The OpenSSL Project Authors. All Rights Reserved.
#
# Licensed under the Apache License 2.0 (the "License").  You may not use
# this file except in compliance with the License.  You can obtain a copy
# in the file LICENSE in the source distribution or at
# https://www.openssl.org/source/license.html

use strict;
use warnings;

use IPC::Open3;
use OpenSSL::Test qw/:DEFAULT srctop_file bldtop_file data_file/;
use OpenSSL::Test::Utils;

setup("test_use_serverinfo");

plan skip_all => "test_use_serverinfo needs sock enabled" if disabled("sock");
plan skip_all => "test_use_serverinfo needs tls < 1.3 enabled"
    if disabled("tls1") && disabled("tls1_1") && disabled("tls1_2");
plan skip_all => "test_use_serverinfo does not run on Windows nor VMS"
    if $^O =~ /^(VMS|MSWin32|msys)$/;

plan tests => 2;

my $shlib_wrap = bldtop_file("util", "shlib_wrap.sh");
my $apps_openssl = bldtop_file("apps", "openssl");
my $test_server = bldtop_file("test", "use_serverinfo_test_server");
my $cert = srctop_file("apps", "server.pem");

sub run_test {
    my ($is_begin_extension_18, $is_extension_18, $is_end_extension_18) = (0, 0, 0);
    my $port = "0";

    my @s_cmd = ($test_server,
                 data_file('test.key'),
                 data_file('test.crt'));

    my $spid = open3(my $sin, my $sout, undef, $shlib_wrap, @s_cmd);
    while (<$sout>) {
        chomp;
        if ($_ =~ /^ACCEPT\s*:\s*(\d+)$/) {
            $port = $1;
            last;
        }
    }
    print STDERR "Port: $port\n";
    print STDERR "Invalid port\n" if ! ok($port);

    # Start up the client
    my @c_cmd = ("s_client", "-connect", ":$port", "-no_tls1_3", "-serverinfo", 18);

    my $cpid = open3(my $cin, my $cout, undef, $shlib_wrap, $apps_openssl, @c_cmd);

    waitpid($cpid, 0);
    waitpid($spid, 0);

    # Check the client output
    while (<$cout>) {
        chomp;
        $is_begin_extension_18 = 1 if /^-----BEGIN SERVERINFO FOR EXTENSION 18-----$/;
        $is_extension_18 = 1 if /^ABIAAwQFBg==$/;
        $is_end_extension_18 = 1 if /^-----END SERVERINFO FOR EXTENSION 18-----$/;
    }

    if (! ok($is_begin_extension_18 && $is_end_extension_18 && $is_extension_18)) {
        print STDERR "Extension 18 not found in client output :-(\n";
    }
}

run_test();
