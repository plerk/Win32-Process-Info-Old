#!/usr/bin/perl -w

use strict;
use Getopt::Std;
use Win32::Process::Info;

$| = 1;

my %opt;

getopts ('bcem:n:pr:su:v:x:', \%opt) or die <<"usage end";

Testbed and demonstrator for Win32::Process::Info V $Win32::Process::Info::VERSION

usage: perl ProcInfo.pl [options] [pid ...]
where the allowed options are:
  -b = brief (PIDs only - uses ListPids, not GetProcInfo)
  -c = elapsed times in clunks (100-nanosecond intervals)
  -e = require an <Enter> to exit
  -mx = report on machine x (valid only with variant WMI)
  -nx = report on process name x (case-insensitive)
  -p = pulist output
  -rn = number of repeats to do
  -s = report SID rather than username with -p
  -u user:password = guess (valid only with WMI)
  -vx = variant (a comma-separated list of 'WMI', 'NT')

Note that you may need to specify domain\\user:password with the -u
option to get it to work.
usage end

$opt{n} = lc $opt{n} if $opt{n};
$opt{r} ||= 1;

my %arg;
if ($opt{u}) {
    my ($usr, $pwd) = split ':', $opt{u};
    $arg{user} = $usr || '';
    $arg{password} = $pwd || '';
    }

my $pi = Win32::Process::Info->new ($opt{m}, $opt{v}, \%arg);
$pi->Set (
    elapsed_in_seconds	=> !$opt{c},
    );

for (my $iter8 = 0; $iter8 < $opt{r}; $iter8++) {
    print STDERR "Information - Iteration @{[$iter8 + 1]} of $opt{r}\n"
	if $opt{r} > 1;
    if ($opt{b}) {
	print "PIDs:\n",
	    map {"    $_\n"} sort {$a <=> $b} $pi->ListPids (@ARGV);
	}
      else {
	my $key = $opt{s} ? 'OwnerSid' : 'Owner';
	print $opt{p} ?
	    sprintf "%-20s %4s  %s\n", 'Process', 'PID', 'User' :
	    "Process info by process:\n";
	foreach my $proc (sort {$a->{ProcessId} <=> $b->{ProcessId}}
		$pi->GetProcInfo (@ARGV)) {
	    next if $opt{n} && lc $proc->{Name} ne $opt{n};
	    if ($opt{p}) {
		printf "%-20s %4d  %s\n",
		    $proc->{Name} || '', $proc->{ProcessId},
		    $proc->{$key} || '';
		}
	      else {
		print "\n$proc->{ProcessId}\n",
		    map {"    $_ => @{[defined $proc->{$_} ?
			$proc->{$_} : '']}\n"} sort keys %$proc;
		}
	    }
	}
    }


if ($opt{e}) {
    print "Press <Enter> to exit: ";
    <>;
    }

