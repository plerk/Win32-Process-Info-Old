=head1 NAME

Win32::Process::Info::WMI - Provide process information via WMI.

=head1 SYNOPSIS

This package fetches process information on a given Windows
machine, using Microsoft's Windows Management Implementation.

 use Win32::Process::Info
 $pi = Win32::Process::Info->new ([machine], 'WMI');
 $pi->Set (elapsed_as_seconds => 0);	# In clunks, not seconds.
 @pids = $pi->ListPids ();	# Get all known PIDs
 @info = $pi->GetProcInfo ();	# Get the max

CAVEAT USER:

This package is B<not> intended to be used independently;
instead, it is a subclass of Win32::Process::Info, and should
only be called via that package.

=head1 DESCRIPTION

This package implements the WMI-specific methods of
Win32::Process::Info.

The following methods should be considered public:

=over 4

=cut

#	Modifications:

# 0.010	02-Sep-2002	T. R. Wyant
#		Initial release under this name.
#
# 0.011	14-Sep-2002	T. R. Wyant
#		Increment version.
#
#	26-Sep-2002	T. R. Wyant
#		Pull variant construction out of loop; we only need
#			three of them, anyway.
#
#	30-Oct-2002	T. R. Wyant
#		Set the Warn level to 0 inside GetProcInfo, to try
#			to supress OLE's annoying exceptions when
#			getting the SID of a process with no owner
#			(e.g. 'idle', 'system').
#
#	31-Oct-2002	T. R. Wyant
#		Reinstate check for executable path before getting
#			user SID and name, as way to bypass system
#			and idle pseudo-processes.
#
#	01-Nov-2002	T. R. Wyant
#		Set the Warn level to 0 around the instantiation of
#			the WMI object, to supress yet another annoying
#			message when WMI not present.

package Win32::Process::Info::WMI;

@ISA = qw{Win32::Process::Info};
$VERSION = '0.011';

use strict;
use Carp;
###use Math::BigInt;
use Time::Local;
use Win32::OLE qw{in with};
use Win32::OLE::Variant;
###use Win32::OLE::Const 'WMI';


#	note that "new" is >>>NOT<<< considered a public
#	method.

my $wmi_const;

sub new {
my $class = shift;
$class = ref $class if ref $class;
my $mach = shift;
$mach =~ s|[\\/]||g if $mach;
$mach = '.' unless $mach;
my $olecls = "winmgmts:{impersonationLevel=impersonate,(Debug)}!//$mach/root/cimv2";
my $old_warn = Win32::OLE->Option ('Warn');
Win32::OLE->Option (Warn => 0);
my $wmi = Win32::OLE->GetObject ($olecls);
Win32::OLE->Option (Warn => $old_warn);
$wmi or croak "Error - Win32::Process::Info::WMI failed to get winmgs object from OLE: ",
	Win32::OLE->LastError;

##require Win32::OLE::Const 'WMI';
require Win32::OLE::Const;
$wmi_const ||= Win32::OLE::Const->Load ($wmi);

# Note that MSDN says that the following doesn't work under NT 4.0.
##$wmi->Security_->Privileges->AddAsString ('SeDebugPrivilege', 1);

my $self = {%Win32::Process::Info::static};
$self->{machine} = $mach;
$self->{wmi} = $wmi;
$self->{_attr} = undef;	# Cache for keys.
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

    CSCreationClassName
    CSName (= machine name)
    Caption (seems to generally equal Name)
    CreationClassName
    CreationDate
    Description (seems to equal Caption)
    ExecutablePath
    KernelModeTime
    MaximumWorkingSetSize
    MinimumWorkingSetSize
    Name
    OSCreationClassName
    OSName
    OtherOperationCount
    OtherTransferCount
    Owner (*)
    OwnerSid (*)
    PageFaults
    ParentProcessId
    PeakWorkingSetSize
    ProcessId
    ReadOperationCount
    ReadTransferCount
    UserModeTime
    WindowsVersion
    WorkingSetSize
    WriteOperationCount
    WriteTransferCount

You may find other keys available as well.

* - Keys marked with an asterisk are computed, and may not always
be present.

=cut

sub _get_proc_objects {
my $self = shift;
my @procs = @_ ?
    map {
	my $pi = $_ eq '.' ? $$ : $_;
	my $obj = $self->{wmi}->Get ("Win32_Process='$pi'");
	Win32::OLE->LastError ? () : ($obj)	
	} @_ :
    (in $self->{wmi}->InstancesOf ('Win32_Process'));

if (@procs && !$self->{_attr}) {
    my $atls = $self->{_attr} = [];
    $self->{_xfrm} = {
	KernelModeTime	=> \&Win32::Process::Info::_clunks_to_desired,
	UserModeTime	=> \&Win32::Process::Info::_clunks_to_desired,
	};
    foreach my $attr (in $procs[0]->{Properties_}) {
	my $name = $attr->{Name};
	my $type = $attr->{CIMType};
	push @$atls, $name;
	$self->{_xfrm}{$name} = \&Win32::Process::Info::_date_to_time_t
	    if $type == $wmi_const->{wbemCimtypeDatetime};
	}
    }
$self->{_attr} = {map {($_->{Name}, $_->{CIMType})}
	in $procs[0]->{Properties_}}
    if (@procs && !$self->{_attr});

return @procs;
}

sub GetProcInfo {
my $self = shift;
my @pinf;
my %username;
my $sid = Variant (VT_BYREF | VT_BSTR, '');
my $user = Variant (VT_BYREF | VT_BSTR, '');
my $domain = Variant (VT_BYREF | VT_BSTR, '');
my $old_warn = Win32::OLE->Option ('Warn');
Win32::OLE->Option (Warn => 0);
foreach my $proc (_get_proc_objects ($self, @_)) {
    my $phash = $self->_build_hash (
	undef, map {($_, $proc->{$_})} @{$self->{_attr}});
    push @pinf, $phash;
    my $oid;

#	The test for executable path is extremely ad-hoc, but the best
#	way I have come up with so far to strain out the System and
#	Idle processes. The methods can misbehave badly on these, and
#	I have found no other way of identifying them. Idle is always
#	process 0, but it seems to me that I have seen once a system
#	whose System process ID was not 8. This test was actually
#	removed at one point, but is reinstated since finding a set of
#	slides on the NT startup which bolsters my confidence in it.
#	But it still looks like ad-hocery to me.

    eval {
	if ($proc->{ExecutablePath} and !$proc->GetOwnerSid ($sid) and
		$oid = $sid->Get ()) {
	    $phash->{OwnerSid} = $oid;
	    unless ($username{$oid}) {
		$username{$oid} =
		    $proc->GetOwner ($user, $domain) ? $oid :
		    "@{[$domain->Get ()]}\\@{[$user->Get ()]}";
		}
	    $phash->{Owner} = $username{$oid};
	    }
	};
    }
Win32::OLE->Option (Warn => $old_warn);
return wantarray ? @pinf : \@pinf;
}

=item @pids = $pi->ListPids ();

This method lists all known process IDs in the system. If
called in scalar context, it returns a reference to the
list of PIDs. If you pass in a list of pids, the return will
be the intersection of the argument list and the actual PIDs
in the system.

=cut

sub ListPids {
my $self = shift;
my @pinf;
foreach my $proc (_get_proc_objects ($self, @_)) {
    push @pinf, $proc->{ProcessId};
    }
return wantarray ? @pinf : \@pinf;
}
1;
__END__
source of the following list:
http://msdn.microsoft.com/library/default.asp?url=/library/en-us/wmisdk/r_32os5_02er.asp
  string Caption  ;
  string CreationClassName  ;
  datetime CreationDate  ;
  string CSCreationClassName  ;
  string CSName  ;
  string Description  ;
  string ExecutablePath  ;
  uint16 ExecutionState  ;
  string Handle  ;
  uint32 HandleCount  ;
  datetime InstallDate  ;
  uint64 KernelModeTime  ;
  uint32 MaximumWorkingSetSize  ;
  uint32 MinimumWorkingSetSize  ;
  string Name  ;
  string OSCreationClassName  ;
  string OSName  ;
  uint64 OtherOperationCount  ;
  uint64 OtherTransferCount  ;
  uint32 PageFaults  ;
  uint32 PageFileUsage  ;
  uint32 ParentProcessId  ;
  uint32 PeakPageFileUsage  ;
  uint64 PeakVirtualSize  ;
  uint32 PeakWorkingSetSize  ;
  uint32 Priority  ;
  uint64 PrivatePageCount  ;
  uint32 ProcessId  ;
  uint32 QuotaNonPagedPoolUsage  ;
  uint32 QuotaPagedPoolUsage  ;
  uint32 QuotaPeakNonPagedPoolUsage  ;
  uint32 QuotaPeakPagedPoolUsage  ;
  uint64 ReadOperationCount  ;
  uint64 ReadTransferCount  ;
  uint32 SessionId  ;
  string Status  ;
  datetime TerminationDate  ;
  uint32 ThreadCount  ;
  uint64 UserModeTime  ;
  uint64 VirtualSize  ;
  string WindowsVersion  ;
  uint64 WorkingSetSize  ;
  uint64 WriteOperationCount  ;
  uint64 WriteTransferCount  ;

=back

=head1 REQUIREMENTS

It should be obvious that this library must run under some
flavor of Windows.

This library uses the following libraries:

  Carp
  Time::Local
  Win32::OLE

As of ActivePerl 630, none of the variant libraries use any libraries
that are not included with ActivePerl. Your milage may vary.

=head1 ACKNOWLEDGMENTS

This module would not exist without the following people:

Jenda Krynicky, whose "How2 create a PPM distribution"
(F<http://jenda.krynicky.cz/perl/PPM.html>) gave me a leg up on
both PPM and tar distributions.

Dave Roth, F<http://www.roth.net/perl/>, author of
B<Win32 Perl Programming: Administrators Handbook>, which is
published by Macmillan Technical Publishing, ISBN 1-57870-215-1

=head1 AUTHOR

Thomas R. Wyant, III (F<Thomas.R.Wyant-III@usa.dupont.com>)

=head1 COPYRIGHT

Copyright 2001,2002 by E. I. DuPont de Nemours and Company, Inc.

This module is free software; you can use it, redistribute it
and/or modify it under the same terms as Perl itself.

=cut

