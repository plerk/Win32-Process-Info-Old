#!/usr/bin/perl -w

use strict;
use Getopt::Std;
use Win32::Process::Info;

$| = 1;

my %opt;

getopts ('bcm:n:pv:x:', \%opt) or die <<"usage end";

Testbed and demonstrator for Win32::Process::Info V $Win32::Process::Info::VERSION

usage: perl ProcInfo.pl [options] [pid ...]
where the allowed options are:
  -b = brief (PIDs only - uses ListPids, not GetProcInfo)
  -c = elapsed times in clunks (100-nanosecond intervals)
  -mx = report on machine x (valid only with variant WMI)
  -nx = report on process name x (case-insensitive)
  -p = pulist output (only get User with variant WMI)
  -vx = variant (a comma-separated list of 'WMI', 'NT')
usage end

$opt{n} = lc $opt{n} if $opt{n};

my $pi = Win32::Process::Info->new ($opt{m}, $opt{v});
$pi->Set (
    elapsed_in_seconds	=> !$opt{c},
    );

if ($opt{b}) {
    print "PIDs:\n",
	map {"    $_\n"} sort {$a <=> $b} $pi->ListPids (@ARGV);
    }
  else {
    print $opt{p} ?
	sprintf "%-20s %4s  %s\n", 'Process', 'PID', 'User' :
	"Process info by process:\n";
    foreach my $proc (sort {$a->{ProcessId} <=> $b->{ProcessId}}
		$pi->GetProcInfo (@ARGV)) {
	next if $opt{n} && lc $proc->{Name} ne $opt{n};
	if ($opt{p}) {
	    printf "%-20s %4d  %s\n",
		$proc->{Name} || '', $proc->{ProcessId}, $proc->{Owner} || '';
	    }
	  else {
	    print "\n$proc->{ProcessId}\n",
		map {"    $_ => @{[defined $proc->{$_} ? $proc->{$_} : '']}\n"} sort keys %$proc;
	    }
	}
    }
