=head1 NAME

Win32::Process::Info::NT - Provide process information via NT-native calls.

=head1 SYNOPSIS


This package fetches process information on a given Windows
machine, using Microsoft Windows NT's native process
information calls.

 use Win32::Process::Info
 $pi = Win32::Process::Info->new ([machine], 'NT');
 $pi->Set (elapsed_as_seconds => 0);	# In clunks, not seconds.
 @pids = $pi->ListPids ();	# Get all known PIDs
 @info = $pi->GetProcInfo ();	# Get the max

CAVEAT USER:

This package does not support access to a remote machine,
because the underlying API doesn't. If you specify a machine
name (other than '', 0, or undef) when you instantiate a
new Win32::Process::Info::NT object, you will get an exception.

This package is B<not> intended to be used independently;
instead, it is a subclass of Win32::Process::Info, and should
only be called via that package.

=head1 DESCRIPTION

The main purpose of the Win32::Process::Info package is to get whatever
information is convenient (for the author!) about one or more Windows
32 processes. GetProcInfo (which see) is therefore the most-important
subroutine in the package. See it for more information.

Unless explicitly stated otherwise, modules, variables, and so
on are considered private. That is, the author reserves the right
to make arbitrary changes in the way they work, without telling
anyone. For subroutines, variables, and so on which are considered
public, the author will make an effort keep them stable, and failing
that to call attention to changes.

Nothing is exported by default, though all the public subroutines are
exportable, either by name or by using the :all tag.

The following subroutines should be considered public:

=over 4

=cut

package Win32::Process::Info::DummyRoutine;

#	The purpose of this is to provide a dummy Call
#	method for those cases where we might not be able
#	to map a subroutine.

sub new {
my $class = shift;
$class = ref $class if ref $class;
my $self = {};
bless $self, $class;
return $self;
}

sub Call {
return undef;
}

# 0.010	02-Sep-2002	T. R. Wyant
#		Initial release under this name.
#
# 0.011	14-Sep-2002	T. R. Wyant
#		Increment version.
#
#	30-Oct-2002	T. R. Wyant
#		Fix warning when -w in effect. Fix provided by Judy
#		Hawkins (of Pitney Bowes, according to her mailing
#		address), and accepted with thanks.

package Win32::Process::Info::NT;

@ISA = qw{Win32::Process::Info};
$VERSION = '0.011';

use strict;
use vars qw {
    $CloseHandle
    $elapsed_in_seconds
    $EnumProcesses
    $EnumProcessModules
    $FileTimeToSystemTime
    $GetCurrentProcId
    $GetModuleFileNameEx
    $GetPriorityClass
    $GetProcessAffinityMask
    $GetProcessIoCounters
    $GetProcessWorkingSetSize
    $GetProcessTimes
    $GetProcessVersion
    $OpenProcess
    $VERSION
    };
use Carp;
use Exporter;
use Time::Local;
use Win32;
use Win32::API;
## use Math::BigInt;
## use Math::BigFloat;


my %_transform = (
	CreationDate => \&Win32::Process::Info::_date_to_time_t,
	KernelModeTime => \&Win32::Process::Info::_clunks_to_desired,
	UserModeTime => \&Win32::Process::Info::_clunks_to_desired,
	);

#@ISA = qw{Exporter};
#@EXPORT = qw{};
#@EXPORT_OK = qw{GetCurrentProcessId GetProcInfo ListPids};
#%EXPORT_TAGS = (
#    all	=> \@EXPORT_OK,
#    );

sub _map {
return Win32::API->new (@_) ||
    croak "Error - Failed to map $_[1] from $_[0]: $^E";
}

sub _map_opt {
return Win32::API->new (@_) ||
    Win32::Process::Info::DummyRoutine->new ();
}

sub new {
my $class = shift;
$class = ref $class if ref $class;
croak "Error - GetProcInfo is unsupported under this flavor of Windows."
    unless Win32::IsWinNT ();
my $mach = shift;
croak "Error - Win32::Process::Info::NT does not support remote operation."
    if $mach;
my $self = {%Win32::Process::Info::static};
delete $self->{variant};
$self->{_xfrm} = \%_transform;
bless $self, $class;
return $self;
}


=item @info = $pi->GetProcInfo ();

This method returns a list of anonymous hashes, each containing
information on one process. If no arguments are passed, the
list represents all processes in the system. You can pass a
list of process IDs, and get out a list of the attributes of
all such processes that actually exist. If you call this
method in scalar context, you get a reference to the list.

What keys are available depend both on the variant in use and
the setting of b<use_wmi_names>. Assuming B<use_wmi_names> is
TRUE, you can hope to get at least the following keys for a
"normal" process (i.e. not the idle process, which is PID 0,
nor the system, which is PID 8) to which you have access:

    CreationDate
    ExecutablePath
    KernelModeTime
    MaximumWorkingSetSize
    MinimumWorkingSetSize
    Name (generally the name of the executable file)
    OtherOperationCount
    OtherTransferCount (= number of bytes transferred)
    ProcessId
    ReadOperationCount
    ReadTransferCount (= number of bytes read)
    UserModeTime
    WriteOperationCount
    WriteTransferCount (= number of bytes read)

All returns are Perl scalars except for KernelModeTime,
UserModeTime, and the I/O statistics; these are Math::BigInt
objects. The I/O statistic keys represent counts if named
*OperationCount, or bytes if named *TransferCount.

Note that:

- The I/O statistic keys will only be present on Windows 2000.

- The MinimumWorkingSetSize and MaximumWorkingSetSize keys have
no apparant relationship to the amount of memory actually
consumed by the process.

The output will contain all processes for which information was
requested, but will not necessarily contain all information for
all processes.

The _status key of the process hash contains the status of
GetProcInfo's request(s) for information. If all information is
present, the status element of the hash will be zero. If there
was any problem getting any of the information, the _status element
will contain the Windows error code ($^E + 0, to be precise). You
might want to look
at it - or not count on the hashes being fully populated (or both!).

=cut

#	The following Perl-stype manifest constants are from windef.h

sub MAX_PATH {260}

#	The following Perl-style manifest constants are from winerror.h

sub ERROR_ACCESS_DENIED       {5}

#	The following Perl-style manifest constants are from winnt.h

sub SYNCHRONIZE                      {0x00100000}
sub STANDARD_RIGHTS_REQUIRED         {0x000F0000}

sub PROCESS_TERMINATE         {0x0001}
sub PROCESS_CREATE_THREAD     {0x0002}
sub PROCESS_VM_OPERATION      {0x0008}
sub PROCESS_VM_READ           {0x0010}
sub PROCESS_VM_WRITE          {0x0020}
sub PROCESS_DUP_HANDLE        {0x0040}
sub PROCESS_CREATE_PROCESS    {0x0080}
sub PROCESS_SET_QUOTA         {0x0100}
sub PROCESS_SET_INFORMATION   {0x0200}
sub PROCESS_QUERY_INFORMATION {0x0400}
sub PROCESS_ALL_ACCESS        {STANDARD_RIGHTS_REQUIRED | SYNCHRONIZE |
                                   0xFFF}

sub GetProcInfo {
my $self = shift;
$CloseHandle ||= _map ('KERNEL32', 'CloseHandle', [qw{N}], 'V');
$GetModuleFileNameEx ||= _map ('PSAPI', 'GetModuleFileNameEx', [qw{N N P N}], 'I');
$GetPriorityClass ||= _map ('KERNEL32', 'GetPriorityClass', [qw{N}], 'I');
$GetProcessAffinityMask ||= _map ('KERNEL32', 'GetProcessAffinityMask', [qw{N P P}], 'I');
$GetProcessIoCounters ||= _map_opt ('KERNEL32', 'GetProcessIoCounters', [qw{N P}], 'I');
$GetProcessTimes ||= _map ('KERNEL32', 'GetProcessTimes', [qw{N P P P P}], 'I');
$GetProcessWorkingSetSize ||= _map ('KERNEL32', 'GetProcessWorkingSetSize', [qw{N P P}], 'I');
$OpenProcess ||= _map ('KERNEL32', 'OpenProcess', [qw{N I N}], 'N');
$EnumProcessModules ||= _map ('PSAPI', 'EnumProcessModules', [qw{N P N P}], 'I');

my $dac = PROCESS_QUERY_INFORMATION | PROCESS_VM_READ;

@_ = ListPids ($self) unless @_;

my @pinf;

my $dat;

foreach my $pid (map {$_ eq '.' ? $$ : $_} @_) {

    $^E = 0;
    $dat = $self->_build_hash (undef, ProcessId => $pid);

    my $prchdl = $OpenProcess->Call ($dac, 0, $pid) or next;

    push @pinf, $dat;

    my ($cretim, $exttim, $knltim, $usrtim);
    $cretim = $exttim = $knltim = $usrtim = ' ' x 8;
    if ($GetProcessTimes->Call ($prchdl, $cretim, $exttim, $knltim, $usrtim)) {
	my $time = _to_char_date ($cretim);
	$self->_build_hash ($dat, CreationDate => $time) if $time;
	$self->_build_hash ($dat,
		KernelModeTime	=> _ll_to_bigint ($knltim),
		UserModeTime	=> _ll_to_bigint ($usrtim));
	}

    my ($minws, $maxws);
    $minws = $maxws = '    ';
    if ($GetProcessWorkingSetSize->Call ($prchdl, $minws, $maxws)) {
	$self->_build_hash ($dat,
		MinimumWorkingSetSize	=> unpack ('L', $minws),
		MaximumWorkingSetSize	=> unpack ('L', $maxws));
	}

    my $procio = '        ' x 6;	# structure is 6 longlongs.
    if ($GetProcessIoCounters->Call ($prchdl, $procio)) {
	my ($ro, $wo, $oo, $rb, $wb, $ob) = _ll_to_bigint ($procio);
	$self->_build_hash ($dat,
		ReadOperationCount	=> $ro,
		ReadTransferCount	=> $rb,
		WriteOperationCount	=> $wo,
		WriteTransferCount	=> $wb,
		OtherOperationCount	=> $oo,
		OtherTransferCount	=> $ob);
	}

    my $modhdl = '    ';	# Module handle better be 4 bytes.
    my $modgot = '    ';

    if ($EnumProcessModules->Call ($prchdl, $modhdl, length $modhdl, $modgot)) {
	$modhdl = unpack ('L', $modhdl);
	my $mfn = ' ' x MAX_PATH;
	if ($GetModuleFileNameEx->Call ($prchdl, $modhdl, $mfn, length $mfn)) {
	    $mfn =~ s/\0.*//;
	    $mfn =~ s/^\\(\w+)/$ENV{$1} ? $ENV{$1} : "\\$1"/ex;
	    $self->_build_hash ($dat,
		ExecutablePath	=> $mfn);
	    $mfn =~ m/\\([^\\]+)$/ and
		$self->_build_hash ($dat, Name => uc $1);
	    }
	}

    $CloseHandle->Call ($prchdl);
    }
  continue {
    $self->_build_hash ($dat, _status => $^E + 0);
    }
return wantarray ? @pinf : \@pinf;
}

sub _to_char_date {
my @result;
$FileTimeToSystemTime ||= Win32::API->new ('KERNEL32', 'FileTimeToSystemTime', [qw{P P}], 'I') or
    croak "Error - Failed to map FileTimeToSystemTime: $^E";
my $systim = '  ' x 8;
foreach (@_) {
    $FileTimeToSystemTime->Call ($_, $systim) or
	croak "Error - FileTimeToSystemTime failed: $^E";
    my $time;
    my ($yr, $mo, $dow, $day, $hr, $min, $sec, $ms) = unpack ('S*', $systim);
    if ($yr == 1601 && $mo == 1 && $day == 1) {
	$time = undef;
	}
      else {
	$time = sprintf ('%04d%02d%02d%02d%02d%02d',
	    $yr, $mo, $day, $hr, $min, $sec);
	}
    push @result, $time;
    }
return @result if wantarray;
return $result[0];
}

sub _ll_to_bigint {
my @result;
foreach (@_) {
    my @data = unpack 'L*', $_;
    while (@data) {
	my $low = shift @data;
	my $high = shift @data;
	push @result, ($high <<= 32) + $low;
	}
    }
return @result if wantarray;
return $result[0];
}

sub _clunks_to_secs {
my @result;
foreach (_ll_to_bigint (@_)) {
    push @result, $_ / 10_000_000;
    }
return @result if wantarray;
return $result[0];
}

=item @pids = $pi->ListPids ()

This subroutine returns a list of all known process IDs in the
system, in no particular order. If called in list context, the
list of process IDs itself is returned. In scalar context, a
reference to the list is returned.

=cut

sub ListPids {
my $self = shift;
my $filter = undef;
$filter = {map {(($_ eq '.' ? $$ : $_), 1)} @_} if @_;
$EnumProcesses ||= _map ('PSAPI', 'EnumProcesses', [qw{P N P}], 'I');
my $psiz = 4;
my $bsiz = 0;
    {
    $bsiz += 1024;
    my $pidbuf = ' ' x $bsiz;
    my $pidgot = '    ';
    $EnumProcesses->Call ($pidbuf, $bsiz, $pidgot) or
	croak "Error - Failed to call EnumProcesses: $^E";
    my $pidnum = unpack ('L', $pidgot);
    redo unless $pidnum < $bsiz;
    $pidnum /= 4;
    my @pids;
    if ($filter) {
	@pids = grep {$filter->{$_}} unpack ("L$pidnum", $pidbuf);
	}
      else {
	@pids = unpack ("L$pidnum", $pidbuf);
	}
    return wantarray ? @pids : \@pids;
    }

}

=back

=head1 REQUIREMENTS

This library uses the following libraries:

 Carp
 Time::Local
 Win32
 Win32::API

As of this writing, all but Win32 and Win32::API are part of the
standard Perl distribution. Win32 is not part of the standard Perl
distribution, but comes with the ActivePerl distribution. Win32::API
comes with ActivePerl as of about build 630, but did not come with
earlier versions. It must be installed before installing this module.

=head1 ACKNOWLEDGMENTS

This module would not exist without the following people:

Aldo Calpini, who gave us Win32::API.

The folks of Cygwin (F<http://www.cygwin.com/>), especially the author
of ps.cc, who is known to me only by the initials "cgf".

Jenda Krynicky, whose "How2 create a PPM distribution"
(F<http://jenda.krynicky.cz/perl/PPM.html>) gave me a leg up on
both PPM and tar distributions.

=head1 AUTHOR

Thomas R. Wyant, III (F<Thomas.R.Wyant-III@usa.dupont.com>)

=head1 COPYRIGHT

Copyright 2001, 2002 by E. I. DuPont de Nemours and Company, Inc.

This module is free software; you can use it, redistribute it
and/or modify it under the same terms as Perl itself.

=cut

1;
