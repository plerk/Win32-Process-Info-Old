=head1 NAME

Win32::Process::Info - Provide process information for Windows 32 systems.

=head1 SYNOPSIS

 use Win32::Process::Info
 $pi = Win32::Process::Info->new ([machine], [variant]);
 $pi->Set (elapsed_as_seconds => 0);	# In clunks, not seconds.
 @pids = $pi->ListPids ();	# Get all known PIDs
 @info = $pi->GetProcInfo ();	# Get the max

CAVEAT USER:

This package covers a multitude of sins - as many as Microsoft has
invented ways to get process info and I have resources and gumption
to code. The key to this mess is the 'variant' argument to the 'new'
method (q.v.).

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

The following methods should be considered public:

=over 4

=cut

#	Modifications:

# 0.010	02-Sep-2002	T. R. Wyant
#		Renamed from Win32::ProcInfo
#		Initial release under name Win32::Process::Info

package Win32::Process::Info;

$VERSION = '0.010';

use strict;
use vars qw{%static};
use Carp;
use Time::Local;
use UNIVERSAL qw{isa};

%static = (
    elapsed_in_seconds	=> 1,
    variant		=> undef,
    );
my %make_variant = (
    NT => sub {
	require Win32::Process::Info::NT;
	Win32::Process::Info::NT->new (@_);
	},
    WMI => sub {
	require Win32::Process::Info::WMI;
	Win32::Process::Info::WMI->new (@_);
	},
    );

my %mutator = (
    elapsed_in_seconds	=> sub {$_[2]},
    variant		=> sub {
	croak "Error - Variant can not be set on an instance."
	    if isa ($_[0], 'Win32::Process::Info');
	foreach (split '\W+', $_[2]) {
	    croak "Error - Variant '$_' is unknown."
		unless exists $make_variant{$_};
	    }
	$_[2]},
    );


=item $pi = Win32::Process::Info->new ([machine], [variant])

This method instantiates a process information object, connected
to the given machine, and using the given variant.

The following variants are currently supported:

NT - Uses the NT-native mechanism. Good on any NT, including
Windows 2000. This variant does not support connecting to
another machine, so the 'machine' argument must be an
empty string (or undef, if you prefer).

WMI - Uses the Windows Management Implementation. Good on Win2K, ME,
and possibly others, depending on their vintage and whether
WMI has been retrofitted.

The default variant is initially 'WMI,NT' (which means to try WMI
first, and NT if WMI fails), but this can be changed using
Win32::Process::Info->Set (variant => whatever).

=cut

sub new {
my $class = shift;
$class = ref $class if ref $class;
my $mach = shift;
my $try = shift || $static{variant} || 'WMI,NT';
my ($self, @probs, $variant);
foreach $variant (grep {$_} split '\W+', $try) {
    eval {
	croak "Error - Variant '$variant' is unknown."
	    unless exists $make_variant{$variant};
	$self = $make_variant{$variant}->($mach);
	};
    if ($self) {
	$static{variant} ||= $variant;
	return $self;
	}
    push @probs, $@;
    }
croak @probs;
}

=item @values = $pi->Get (attributes ...)

This method returns the values of the listed attributes. If
called in scalar context, it returns the value of the first
attribute specified, or undef if none was. An exception is
raised if you specify a non-existent attribute.

This method can also be called as a class method (that is, as
Win32::Process::Info->Get ()) to return default attributes values.

The relevant attribute names are:

B<elapsed_as_seconds> is TRUE to convert elapsed user and
kernel times to seconds. If FALSE, they are returned in
clunks (that is, hundreds of nanoseconds). The default is
TRUE.

B<variant> is the variant of the process info code in use,
and should be zero or more of 'WMI' or 'NT', separated by
commas. 'WMI' selects the Windows Management Implementation, and
'NT' selects the Windows NT native interface. B<variant> can
only be set on the class, not the instance. If you set
B<variant> to an empty string (the default), the next "new"
will iterate over all possibilities, and set B<variant> to
the first one that actually works.

B<machine> is the name of the machine connected to. This is
not available as a class attribute.

=cut

sub Get {
my $self = shift;
$self = \%static unless ref $self;
my @vals;
foreach my $name (@_) {
    croak "Error - Attribute '$name' does not exist."
	unless exists $self->{$name};
    push @vals, $self->{$name};
    }
return wantarray ? @vals : $vals[0];
}

=item @values = $pi->Set (attribute => value ...)

This method sets the values of the listed attributes,
returning the values of all attributes listed if called in
list context, or of the first attribute listed if called
in scalar context.

This method can also be called as a class method (that is, as
Win32::Process::Info->Set ()) to change default attribute values.

The relevant attribute names are the same as for Get.
However:

B<elapsed_as_seconds> is TRUE to convert elapsed user and
kernel times to seconds. If FALSE, they are returned in
clunks (that is, hundreds of nanoseconds). The default is
TRUE.

B<variant> is read-only at the instance level. That is,
Win32::Process::Info->Set (variant => 'NT') is OK, but
$pi->Set (variant => 'NT') will raise an exception.

B<machine> is not available as a class attribute, and is
read-only as an instance attribute. It is B<not> useful for
discovering your machine name - if you instantiated the
object without specifying a machine name, you will get
nothing useful back.

=cut

sub Set {
my $self = shift;
croak "Error - Set requires an even number of arguments."
    if @_ % 2;
$self = \%static unless ref $self;
my @vals;
while (@_) {
    my $name = shift;
    my $val = shift;
    croak "Error - Attribute '$name' does not exist."
	unless exists $self->{$name};
    croak "Error - Attribute '$name' is read-only."
	unless exists $mutator{$name};
    $self->{$name} = $mutator{$name}->($self, $name, $val);
    push @vals, $self->{$name};
    }
return wantarray ? @vals : $vals[0];
}

=item @pids = $pi->ListPids ();

This method lists all known process IDs in the system. If
called in scalar context, it returns a reference to the
list of PIDs. If you pass in a list of pids, the return will
be the intersection of the argument list and the actual PIDs
in the system.

=cut

sub ListPids {
croak "Error - Whoever coded this forgot to override ListPids.";
}

=item @info = $pi->GetProcInfo ();

This method returns a list of anonymous hashes, each containing
information on one process. If no arguments are passed, the
list represents all processes in the system. You can pass a
list of process IDs, and get out a list of the attributes of
all such processes that actually exist. If you call this
method in scalar context, you get a reference to the list.

What keys are available depends on the variant in use.
You can hope to get at least the following keys for a
"normal" process (i.e. not the idle process, which is PID 0,
nor the system, which is some small indeterminate PID) to
which you have access:

    CreationDate
    ExecutablePath
    KernelModeTime
    MaximumWorkingSetSize
    MinimumWorkingSetSize
    Name (generally the name of the executable file)
    ProcessId
    UserModeTime

You may find other keys available as well, depending on which
operating system you're using, and which variant of Process::Info
you're using.

=cut

sub GetProcInfo {
croak "Error - Whoever coded this forgot to override GetProcInfo.";
}

#
#	$self->_build_hash ([hashref], key, value ...)
#	builds a process info hash out of the given keys and values.
#	The keys are assumed to be the WMI keys, and will be trans-
#	formed if needed. The values will also be transformed if
#	needed. The resulting hash entries will be placed into the
#	given hash if one is present, or into a new hash if not.
#	Either way, the hash is returned.

sub _build_hash {
my $self = shift;
my $hash = shift || {};
while (@_) {
    my $key = shift;
    my $val = shift;
    $val = $self->{_xfrm}{$key}->($self, $val)
	if (exists $self->{_xfrm}{$key});
    $hash->{$key} = $val;
    }
return $hash;
}


#	$self->_clunks_to_desired (clunks ...)
#	converts elapsed times in clunks to elapsed times in
#	seconds, PROVIDED $self->{elapsed_in_seconds} is TRUE.
#	Otherwise it simply returns its arguments unmodified.

sub _clunks_to_desired {
my $self = shift;
@_ = map {$_ / 10_000_000} @_ if $self->{elapsed_in_seconds};
return wantarray ? @_ : $_[0];
}

#	$self->_date_to_time_t (date ...)
#	converts the input dates (assumed YYYYmmddhhMMss) to
#	Perl internal time, returning the results. The "self"
#	argument is unused.

sub _date_to_time_t {
my $self = shift;
my @result;
foreach (@_) {
    if ($_) {
	my ($yr, $mo, $da, $hr, $mi, $sc) = m/^(\d{4})(\d{2})(\d{2})(\d{2})(\d{2})(\d{2})/;
	--$mo;
	my $val = timelocal ($sc, $mi, $hr, $da, $mo, $yr);
	push @result, $val;
	}
      else {
	push @result, undef;
	}
    }
return @result if wantarray;
return $result[0];
}

1;
__END__

=back

=head1 REQUIREMENTS

It should be obvious that this library must run under some
flavor of Windows.

This library uses the following libraries:

 Carp
 Time::Local
 Win32::API (if using the NT-native variant)
 Win32::ODBC (if using the WMI variant)

As of ActivePerl 630, none of this uses any packages that are not
included with ActivePerl. Your mileage may vary.

=head1 HISTORY

 0.010 Released as Win32::Process::Info

=head1 ACKNOWLEDGMENTS

This module would not exist without the following people:

Aldo Calpini, who gave us Win32::API.

Jan Krynicky, whose "How2 create a PPM distribution"
(F<http://jenda.krynicky.cz/perl/PPM.html>) gave me a leg up on
both PPM and tar distributions.

Dave Roth, F<http://www.roth.net/perl/>, author of
B<Win32 Perl Programming: Administrators Handbook>, which is
published by Macmillan Technical Publishing, ISBN 1-57870-215-1

Dan Sugalski F<sugalskd@osshe.edu>, author of VMS::Process, where
I got (for good or ill) the idea of just grabbing all the data
I could find on a process and smashing it into a big hash.

The folks of Cygwin (F<http://www.cygwin.com/>), especially the author
of ps.cc, who is known to me only by the initials "cgf".

=head1 AUTHOR

Thomas R. Wyant, III (F<Thomas.R.Wyant-III@usa.dupont.com>)

=head1 COPYRIGHT

Copyright 2001, 2002 by E. I. DuPont de Nemours and Company, Inc.
All rights reserved.

This module is free software; you can use it, redistribute it
and/or modify it under the same terms as Perl itself.

=cut

