=head1 NAME

Win32::Process::Info - Provide process information for Windows 32 systems.

=head1 SYNOPSIS

 use Win32::Process::Info;
 $pi = Win32::Process::Info->new ([machine], [variant]);
 $pi->Set (elapsed_as_seconds => 0);	# In clunks, not seconds.
 @pids = $pi->ListPids ();	# Get all known PIDs
 @info = $pi->GetProcInfo ();	# Get the max
 %subs = $pi->Subprocesses ();	# Figure out subprocess relationships.

CAVEAT USER:

This package covers a multitude of sins - as many as Microsoft has
invented ways to get process info and I have resources and gumption
to code. The key to this mess is the 'variant' argument to the 'new'
method (q.v.).

=head1 DESCRIPTION

The main purpose of the Win32::Process::Info package is to get whatever
information is convenient (for the author!) about one or more Windows
32 processes. GetProcInfo (which see) is therefore the most-important
method in the package. See it for more information.

Unless explicitly stated otherwise, modules, variables, and so
on are considered private. That is, the author reserves the right
to make arbitrary changes in the way they work, without telling
anyone. For methods, variables, and so on which are considered
public, the author will make an effort keep them stable, and failing
that to call attention to changes.

The following methods should be considered public:

=over 4

=cut

#	Modifications:

# 0.010	02-Sep-2002	T. R. Wyant
#		Renamed from Win32::ProcInfo
#		Initial release under name Win32::Process::Info
#
# 0.011	14-Sep-2002	T. R. Wyant
#		Incremented version number
#		Added method "Version".
#
# 0.012	06-Nov-2002	T. R. Wyant
#		Incremented version number
#		Made attributes beginning with "_" hidden.
#		Add attribute _mutator, containing a reference to
#			%mutator.
#
#	12-Nov-2002	T. R. Wyant
#		Build hash argument for subclass instantiators.
#		Document this, and the use of the various keys.
#
#	07-Dec-2002	T. R. Wyant
#		Check environment variable
#		PERL_WIN32_PROCESS_INFO_VARIANT for the default
#		variant(s), if none is specified.
#
# 0.013	13-Mar-2003	T. R. Wyant
#		Remove dependencies on Win32::API, Win32::OLE, and
#			Win32API::Registry from Makefile.PL, since
#			these are conditional.
#
# 0.013_2 21-May-2003	T. R. Wyant
#		Add the %variant_support hash in response to INIT block
#			errors in Win32::API when (effectively)
#			require-d when the object is new-ed.
#
# 0.013_21 05-Jun-2003	T. R. Wyant
#		Found a need to tweak the WMI variant. Wouldn't have
#			incremented here, but wanted a different package
#			number since I had previously send out 0.013_2
#			privately. The tweak was the manual skipping of
#			processes in response to the contents of
#			$ENV{PERL_WIN32_PROCESS_INFO_WMI_PARIAH}
#
# 0.013_22 20-Jun-2003	T. R. Wyant
#		No longer assert the debug privilege by default. Only
#			do it $ENV{PERL_WIN32_PROCESS_INFO_WMI_DEBUG}
#			is TRUE in the Perl sense.
#		As a consequence of the effects of the above, default
#			the pariah list to empty.
#		Enhanced the test to skip the NT variant if it can't
#			find all the DLLs.
#
# 0.013_23 26-Jun-2003	T. R. Wyant
#		Added method Subprocesses. Because I needed it.
#
# 0.014	27-Jun-2003	T. R. Wyant
#		Wrapped up latest version, released to CPAN.
#
# 0.014_01 25-Jul-2003	T. R. Wyant
#		Straightened out some of the POD.
#		Added hash argument assert_debug_priv to 'new' method.
#			This is legal for all variants, but only
#			affects the WMI variant.
# 0.014_02 16-Aug-2003	T. R. Wyant
#		Added missing semicolon after "use Win32::Process::Info"
#			in the synopsis.
#
# 1.000 09-Oct-2003	T. R. Wyant
#		When the only thing you've fixed in the last two months
#			is the docs, it's time to call it production
#			code. And if _that_ statement doesn't flush
#			out more problems, nothing will.
#
# 1.001	05-Jan-2004	T. R. Wyant
#		No changes to the code itself. But removed the
#			dependency on Win32 in Makefile.PL because
#			PPM3 chokes on it, and I figure anyone who isn't
#			using PPM is smart enough to read the Readme.
#
# 1.001_01 24-Feb-2004	T. R. Wyant
#		Failed attempt to fix WMI memory leak. But it's clearly
#		associated with the use of Win32::OLE::Variant objects
#		to retrieve the owner information, because the code
#		appears not to leak if we don't do this. Versions prior
#		to this one leaked anyway, because the Variant objects
#		were allocated whether or not they were used. But this
#		version doesn't allocate them unless they are to be
#		used.
#
# 1.002	07-Jun-2004	T. R. Wyant
#		Document leaks under WMI, and how to minimize. Document
#		related modules.
#
# 1.003 19-Dec-2004	T. R. Wyant
#		Remove the "_PRIV" from the end of environment variable
#		name PERL_WIN32_PROCESS_INFO_WMI_DEBUG in the POD.
#		Record the variant name in the object.
#		Clarify (hopefully) the PERL_WIN32_PROCESS_INFO_VARIANT
#		documentation.
#		Document current whereabouts of Win32::IProc - or at
#		least the sad remnants of it.
# 1.004	30-Dec-2004	T. R. Wyant
#		No code change. Removed the commented-out dependencies
#		in Makefile.PL, since sometime in the last 6 months
#		someone has enhanced CPAN's validation to generate
#		a bug report when I do this. The only hard-and-fast
#		dependency is on Win32, but ActiveState's PPM3
#		chokes on this.
#
# 1.005 15-Mar-2005	T. R. Wyant
#		Moved assertion of seDebugPriv in the NT variant to
#		stop token handle leak.
#		Turned off $^W for timelocal call, since it throws
#		random warnings otherwise.
# 1.006 23-Sep-2005 T. R. Wyant
#		Skip non-existent processes in the Subprocesses method.

package Win32::Process::Info;

$VERSION = 1.006;

use strict;
use vars qw{%mutator %static};

use Carp;
use File::Spec;
use Time::Local;
use UNIVERSAL qw{isa};

%static = (
    elapsed_in_seconds	=> 1,
    variant		=> $ENV{PERL_WIN32_PROCESS_INFO_VARIANT},
    );

#	The real reason for the %variant_support hash is to deal with
#	the apparant inability of Win32::API to be 'require'-d anywhere
#	but in a BEGIN block. The 'unsupported' key is intended to be
#	used as a 'necessary but not required' criterion; that is, if
#	'unsupported' is true, there's no reason to bother; but if it's
#	false, there may still be problems of some sort. This is par-
#	ticularly true of WMI, where the full check is rather elephan-
#	tine.
#
#	While I was at it, I decided to consolidate all the variant-
#	specific information in one spot and, while I was at it, write
#	a variant checker utility.

my %variant_support;
BEGIN {
%variant_support = (
    NT => {
	make => sub {
		require Win32::Process::Info::NT;
		Win32::Process::Info::NT->new (@_);
		},
	unsupported => eval {
		return "Your OS is not a member of the Windows NT family"
		    unless Win32::IsWinNT ();
		return "I can not find Win32::API"
		    unless require Win32::API;
		my @path = split ';', $ENV{Path};
DLL_LOOP:
		foreach my $dll (qw{PSAPI.DLL ADVAPI32.DLL KERNEL32.DLL}) {
		    foreach my $loc (@path) {
			next DLL_LOOP if -e File::Spec->catfile ($loc, $dll);
			}
		    return "I can not find $dll";
		    }
		return 0;
		} || $@,
	},
    WMI => {
	make => sub {
		require Win32::Process::Info::WMI;
		Win32::Process::Info::WMI->new (@_);
		},
	unsupported => eval {
		return "I can not find Win32::OLE"
		    unless require Win32::OLE;
		return 0;
		},
	},
    );
}
sub _check_variant {
croak "Error - Variant '$_[0]' is unknown."
    unless exists $variant_support{$_[0]};
croak "Error - Variant '$_[0]' is unsupported on your configuration. $variant_support{$_[0]}{unsupported}"
    if $variant_support{$_[0]}{unsupported};
return 1;
}

%mutator = (
    elapsed_in_seconds	=> sub {$_[2]},
    variant		=> sub {
	croak "Error - Variant can not be set on an instance."
	    if isa ($_[0], 'Win32::Process::Info');
	foreach (split '\W+', $_[2]) {
	    _check_variant ($_);
	    }
	$_[2]},
    );


=item $pi = Win32::Process::Info->new ([machine], [variant], [hash])

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

The initial default variant comes from environment variable
PERL_WIN32_PROCESS_INFO_VARIANT. If this is not found, it will be
'WMI,NT', which means to try WMI first, and NT if WMI fails. This can
be changed using Win32::Process::Info->Set (variant => whatever).

The hash argument is a hash reference to additional arguments, if
any. The hash reference can actually appear anywhere in the argument
list, though positional arguments are illegal after the hash reference.

The following hash keys are supported:

  variant => corresponds to the 'variant' argument (all)
  assert_debug_priv => assert debug if available (all) This
	only has effect under WMI. The NT variant always
	asserts debug. You want to be careful doing this
	under WMI if you're fetching the process owner
	information, since the script can be badly behaved
	(i.e. die horribly) for those processes whose
	ExecutablePath is only available with the debug
	privilege turned on.
  host => corresponds to the 'machine' argument (WMI)
  user => username to perform operation under (WMI)
  password => password corresponding to the given
	username (WMI)

ALL hash keys are optional. SOME hash keys are only supported under
certain variants. These are indicated in parentheses after the
description of the key. It is an error to specify a key that the
variant in use does not support.

=cut

my @argnam = qw{host variant};
sub new {
my $class = shift;
$class = ref $class if ref $class;
my %arg;
my ($self, @probs, $variant);

my $inx = 0;
foreach my $inp (@_) {
    if (ref $inp eq 'HASH') {
	foreach my $key (keys %$inp) {$arg{$key} = $inp->{$key}}
	}
      elsif (ref $inp) {
	croak "Error - Argument may not be ${[ref $inp]} reference.";
	}
      elsif ($argnam[$inx]) {
	$arg{$argnam[$inx]} = $inp;
	}
      else {
	croak "Error - Too many positional arguments.";
	}
    $inx++;
    }

my $mach = $arg{host} or delete $arg{host};
my $try = $arg{variant} || $static{variant} || 'WMI,NT';
foreach $variant (grep {$_} split '\W+', $try) {
    eval {
	_check_variant ($variant);
	$self = $variant_support{$variant}{make}->(\%arg);
	};
    if ($self) {
	$static{variant} ||= $variant;
	$self->{variant} = $variant;
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

B<variant> is the variant of the Process::Info code in use,
and should be zero or more of 'WMI' or 'NT', separated by
commas. 'WMI' selects the Windows Management Implementation, and
'NT' selects the Windows NT native interface.

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
    croak "Error - Attribute '$name' is private."
	if $name =~ m/^_/;
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

B<variant> is read-only at the instance level. That is,
Win32::Process::Info->Set (variant => 'NT') is OK, but
$pi->Set (variant => 'NT') will raise an exception. If
you set B<variant> to an empty string (the default), the
next "new" will iterate over all possibilities (or the
contents of environment variable
PERL_WIN32_PROCESS_INFO_VARIANT if present), and set
B<variant> to the first one that actually works.

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
my $mutr = $self->{_mutator} || \%mutator;
my @vals;
while (@_) {
    my $name = shift;
    my $val = shift;
    croak "Error - Attribute '$name' does not exist."
	unless exists $self->{$name};
    croak "Error - Attribute '$name' is read-only."
	unless exists $mutr->{$name};
    $self->{$name} = $mutr->{$name}->($self, $name, $val);
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

This method also optionally takes as its first argument a reference
to a hash of option values. The only supported key is:

    no_user_info => 1
	Do not return keys Owner and OwnerSid, even if available.
	These tend to be time-consuming, and can cause problems
	under the WMI variant.

=cut

sub GetProcInfo {
croak "Error - Whoever coded this forgot to override GetProcInfo.";
}

=item %subs = $pi->Subprocesses ([pid ...])

This method takes as its argument a list of PIDs, and returns a hash
indexed by PID and containing, for each PID, a reference to a list of
all subprocesses of that process. If those processes have subprocesses
as well, you will get the sub-sub processes, and so ad infinitum, so
you may well get back more hash keys than you passed process IDs. Note
that the process of finding the sub-sub processes is iterative, not
recursive; so you don't get back a tree.

If no argument is passed, you get all processes in the system.

If called in scalar context you get a reference to the hash.

This method works off the ParentProcessId attribute. Not all variants
support this. If the variant you're using doesn't support this
attribute, you get back an empty hash. Specifically:

 NT -> unsupported
 WMI -> supported

=cut

sub Subprocesses {
my $self = shift;
my %prox = map {($_->{ProcessId} => $_)}
	@{$self->GetProcInfo ({no_user_info => 1})};
my %subs;
my $rslt = \%subs;
my $key_found;
foreach my $proc (values %prox) {
    $subs{$proc->{ProcessId}} ||= [];
    next unless $proc->{ParentProcessId};
    $key_found++;
    next unless $prox{$proc->{ParentProcessId}};
    push @{$subs{$proc->{ParentProcessId}}}, $proc->{ProcessId};
    }
my %listed;
return %listed unless $key_found;
if (@_) {
    $rslt = \%listed;
    while (@_) {
	my $pid = shift;
    next unless $subs{$pid};	# TRW 1.006
	next if $listed{$pid};
	$listed{$pid} = $subs{$pid};
	push @_, @{$subs{$pid}};
	}
    }
return wantarray ? %$rslt : $rslt;
}

=item print "$pi Version = @{[$pi->Version ()]}\n"

This method just returns the version number of the
Win32::Process::Info object.

=cut

sub Version {
return $Win32::Process::Info::VERSION;
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
@_ = map {defined $_ ? $_ / 10_000_000 : undef} @_ if $self->{elapsed_in_seconds};
return wantarray ? @_ : $_[0];
}

#	$self->_date_to_time_t (date ...)
#	converts the input dates (assumed YYYYmmddhhMMss) to
#	Perl internal time, returning the results. The "self"
#	argument is unused.


sub _date_to_time_t {
my $self = shift;
my @result;
local $^W;	# Prevent Time::Local 1.1 from complaining. This appears
$^W = 0;	# to be fixed in 1.11, but since Time::Local is part of
		# the ActivePerl core, there's no PPM installer for it.
		# At least, not that I can find.
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

=head1 ENVIRONMENT

This package is sensitive to a number of environment variables.
Note that these are normally consulted only when the package
is initialized (i.e. when it's "used" or "required").

PERL_WIN32_PROCESS_INFO_VARIANT

If present, specifies which variant(s) are tried, in which
order. The default behaviour is equivalent to specifying
'WMI,NT'. This environment variable is consulted when you
"use Win32::Process::Info;". If you want to change it in
your Perl code you should use the static Set () method.

PERL_WIN32_PROCESS_INFO_WMI_DEBUG

If present and containing a value Perl recognizes as true,
causes the WMI variant to assert the "Debug" privilege.
This has the advantage of returning more full paths, but
the disadvantage of tending to cause Perl to die when
trying to get the owner information on the newly-accessable
processes.

PERL_WIN32_PROCESS_INFO_WMI_PARIAH

If present, should contain a semicolon-delimited list of process names
for which the package should not attempt to get owner information. '*'
is a special case meaning 'all'. You will probably need to use this if
you assert PERL_WIN32_PROCESS_INFO_WMI_DEBUG.

=head1 REQUIREMENTS

It should be obvious that this library must run under some
flavor of Windows.

This library uses the following libraries:

 Carp
 Time::Local
 Win32::API (if using the NT-native variant)
 Win32API::Registry (if using the NT-native variant)
 Win32::ODBC (if using the WMI variant)

As of ActivePerl 630, none of this uses any packages that are not
included with ActivePerl. Your mileage may vary.

=head1 HISTORY

 0.010 Released as Win32::Process::Info
 0.011 Added Version method
       Fixed warning in NT.pm when -w in effect. Fix provided
           by Judy Hawkins (of Pitney Bowes, according to her
           mailing address), and accepted with thanks.
 0.012 Hid attributes beginning with "_".
 0.013 Use environment variable PERL_WIN32_PROCESS_INFO_VARIANT
           to specify the default variant list.
       Add a hash reference argument to new (); use this to
           specify username and password to the WMI variant.
       Turn on debug privilege in NT variant. This also resulted
           in dependency on Win32API::Registry.
       Return OwnerSid and Owner in NT variant.
 0.014 Remove conditional dependencies from Makefile.PL
       Track changes in Win32::API. Can no longer "require" it.
       WMI variant no longer asserts debug privilege by default.
       Use environment variable PERL_WIN32_PROCESS_INFO_WMI_DEBUG
          to tell the WMI variant whether to assert debug.
       Use environment variable PERL_WIN32_PROCESS_INFO_WMI_PARIAH
          to encode processes to skip when determining the owner.
       Add optional first hash ref argument to GetProcInfo.
       Add Subprocesses method.
 1.000 Add assert_debug_priv hash argument to the 'new' method.
       Fix documentation, both pod errors and actual doc bugs.
       When the only thing you've done in two months is add a
           semicolon to a comment, it's probably time to call it
           production code.
 1.001 Removed dependency on Win32. We still need it, of course,
       but PPM3 chokes on it, and I figure anyone who IS using
       PPM3 already has it, and anyone who ISN'T is smart enough
       to figure out what's going on - or at least read the Readme.
 1.002 Document leaky behaviour of WMI variant, and try to make it
       leak less. Document related modules.
 1.003 Documented PERL_WIN32_PROCESS_INFO_WMI_DEBUG correctly
       (the docs had a _PRIV on the end).
       Recorded the variant name in the object.
       Clarified (hopefully) the docs on how to use the
       PERL_WIN32_PROCESS_INFO_VARIANT environment variable.
       Added the current status and whereabouts of
       Win32::IProc. Thanks to Eric Bluestein
       (http://www.emblue.com/) for pointing this out.
 1.004 Remove commented-out dependencies in Makefile.PL,
       since CPAN's now checking. The only one that really
       counts is Win32, but ActiveState's PPM3 chokes on
       this, or at least did as of January 2001.
 1.005 Addressed token handle leak in the NT variant.
 1.006 Silently skip non-existent processes in the Subprocesses
       method. Fix provided by Kirk Baucom of Itron, and accepted
       with thanks.

=head1 BUGS

The WMI variant leaks memory - badly for 1.001 and earlier. After
1.001 it only leaks badly if you retrieve the process owner
information. If you're trying to write a daemon, the NT variant
is recommended. If you're stuck with WMI, set the no_user_info flag
when you call GetProcInfo. This won't stop the leaks, but it minimizes
them, at the cost of not returning the username or SID.

=head1 RESTRICTIONS

You can not "require" this library except in a BEGIN block. This is a
consequence of the use of Win32::API, which has the same restriction,
at least in some versions.

=head1 RELATED MODULES

Win32::Process::Info focuses on returning static data about a process.
If this module doesn't do what you want, maybe one of the following
ones will.

=over 4

=item Win32::PerfLib by Jutta M. Klebe

This module focuses on performance counters. It is a ".xs" module,
and requires Visual C++ 6.0 to install. But it's also part of LibWin32,
and should come with ActivePerl.

=item Win32::IProc by Amine Moulay Ramdane

This module is no longer supported, which is a shame because it returns
per-thread information as well. As of December 27, 2004, Jenda Krynicky
(F<http://jenda.krynicky.cz/>) was hosting a PPM kit in PPM repository
F<http://jenda.krynicky.cz/perl/>, which may be usable. But the source
for the DLL files is missing, so if some Windows upgrade breaks it
you're out of luck.

=item Win32API::ProcessStatus, by Ferdinand Prantl

This module focuses on the .exe and .dll files used by the process. It
is a ".xs" module, requiring Visual C++ 6.0 and psapi.h to install.

=item pulist

This is not a Perl module, it's an executable that comes with the NT
resource kit.

=back

=head1 ACKNOWLEDGMENTS

This module would not exist without the following people:

Aldo Calpini, who gave us Win32::API.

Jenda Krynicky, whose "How2 create a PPM distribution"
(F<http://jenda.krynicky.cz/perl/PPM.html>) gave me a leg up on
both PPM and tar distributions.

Dave Roth, F<http://www.roth.net/perl/>, author of
B<Win32 Perl Programming: Administrators Handbook>, which is
published by Macmillan Technical Publishing, ISBN 1-57870-215-1

Dan Sugalski F<sugalskd@osshe.edu>, author of VMS::Process, where
I got (for good or ill) the idea of just grabbing all the data
I could find on a process and smashing it into a big hash.

The folks of Cygwin (F<http://www.cygwin.com/>), especially Christopher
G. Faylor, author of ps.cc.

Judy Hawkins of Pitney Bowes, for providing testing and patches for
NT 4.0 without WMI.

=head1 AUTHOR

Thomas R. Wyant, III (F<wyant at cpan dot org>)

=head1 COPYRIGHT

Copyright 2001, 2002, 2003, 2004, 2005 by
E. I. DuPont de Nemours and Company, Inc.
All rights reserved.

This module is free software; you can use it, redistribute it
and/or modify it under the same terms as Perl itself.

=cut

