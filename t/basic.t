#!/usr/bin/perl -w

use strict;
use Test;
use Win32;
use Win32::OLE;

my $old_warn = Win32::OLE->Option ('Warn');	# Sure wish I could localize this baby.
Win32::OLE->Option (Warn => 0);
my $wmi = Win32::OLE->GetObject ('winmgmts:{impersonationLevel=impersonate,(Debug)}!//./root/cimv2');
my $proc = $wmi->Get ("Win32_Process='$$'") if $wmi;
$wmi = undef unless $wmi && $proc;
Win32::OLE->Option (Warn => $old_warn);

print "# Information - WMI object = ", defined $wmi ? "'$wmi'\n" : "undefined\n";
print "# Information - WMI process object = ", defined $proc ? "'$proc'\n" : "undefined\n";
print "# Win32::OLE->LastError = @{[Win32::OLE->LastError () || 'none']}\n";

my %skip = (
    NT	=> (Win32::IsWinNT () ? 0 : "Skip Windows NT (or 2000) required"),
    WMI	=> ($wmi ? 0 : "Skip WMI required"),
    );
$ENV{PERL_WIN32_PROCESS_INFO_VARIANT} and do {
    my %var = map {($_, 1)} split ',', uc $ENV{PERL_WIN32_PROCESS_INFO_VARIANT};
    foreach (keys %skip) {
	$skip{$_} ||= 'Skip not in $ENV{PERL_WIN32_PROCESS_INFO_VARIANT}'
	    unless $var{$_};
	}
    };

foreach (@ARGV) {$skip{$_} = "Skip user request" unless $skip{$_}}

my $test_num = 1;
######################### We start with some black magic to print on failure.

# (It may become useful if the test is moved to ./t subdirectory.)

# Note - number of tests is 2 (load and version) + 7 * number of variants

my $loaded;
BEGIN { $| = 1; plan (tests => 16);
    print "# Test 1 - Loading the library.\n"}
END {print "not ok 1\n" unless $loaded;}
use Win32::Process::Info;
$loaded = 1;
ok ($loaded);

######################### End of black magic.

$test_num++;
print "# Test $test_num - See if we can get our version.\n";
ok (Win32::Process::Info::Version () eq $Win32::Process::Info::VERSION);


foreach my $variant (qw{NT WMI}) {

    my $skip = $skip{$variant};
    print "# Testing variant $variant. Skip = '$skip'\n";

    $test_num++;
    print "# Test $test_num - Instantiating the $variant variant.\n";
    my $pi = Win32::Process::Info->new (undef, $variant) unless $skip;
    skip ($skip, $pi);
    $skip ||= !$pi;


    $test_num++;
    print "# Test $test_num - Ability to list processes.\n";
    my @pids = $pi->ListPids () unless $skip;
    skip ($skip, scalar @pids);


    $test_num++;
    print "# Test $test_num - Our own PID should be in the list.\n";
    my @mypid = grep {$$ eq $_} @pids;
    skip ($skip, scalar @mypid);


    $test_num++;
    print "# Test $test_num - Ability to get process info.\n";
    my @pinf = $pi->GetProcInfo () unless $skip;
    skip ($skip, scalar @pinf);


    $test_num++;
    print "# Test $test_num - Ability to get our own info.\n";
    my ($me) = $pi->GetProcInfo ($$) unless $skip;
    skip ($skip, $me);


    $test_num++;
    print "# Test $test_num - Our own process should be running Perl.\n";
    skip ($skip, $me->{Name}, qr{(?i:perl)});


    $test_num++;
    print "# Test $test_num - Our own process should be under our username.\n";
    my ($domain, $user) = $skip || !$me->{Owner} ? ('', '') :
	split '\\\\', $me->{Owner};
    skip ($skip, $user eq getlogin);
    }
