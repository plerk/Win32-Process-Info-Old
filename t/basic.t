use Test;

my $test_num = 1;
######################### We start with some black magic to print on failure.

# (It may become useful if the test is moved to ./t subdirectory.)

BEGIN { $| = 1; plan (tests => 6);
    print "# Test 1 - Loading the library.\n"}
END {print "not ok 1\n" unless $loaded;}
use Win32::Process::Info;
$loaded = 1;
ok ($loaded);

######################### End of black magic.


$test_num++;
print "# Test $test_num - Instantiating an object.\n";
my $pi = Win32::Process::Info->new ();
ok ($pi);


$test_num++;
print "# Test $test_num - Ability to list processes.\n";
my @pids = $pi->ListPids ();
ok (@pids);


$test_num++;
print "# Test $test_num - Our own PID should be in the list.\n";
my @mypid = grep {$$ eq $_} @pids;
ok (@mypid);


#	The following is skipped until I figure out how to
#	prevent it from throwing exceptions when run under
#	the test harness. It works fine interactively.
##$test_num++;
##print "# Test $test_num - Ability to get process info. Skipped.\n";
##my @pinf = $pi->GetProcInfo ();
##ok (@pinf);


$test_num++;
print "# Test $test_num - Ability to get our own info.\n";
my ($me) = $pi->GetProcInfo ($$);
ok ($me);


$test_num++;
print "# Test $test_num - Our own process should be running Perl.\n";
ok ($me->{Name}, qr{(?i:perl)});

