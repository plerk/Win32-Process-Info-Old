use Config;
use ExtUtils::MakeMaker;

my $vers = $] >= 5.008 ? '-5.8' : '';

WriteMakefile (
	NAME => 'Win32::Process::Info',
	VERSION_FROM => 'Info.pm',
	PREREQ_PM => {
			},
#	'linkext' => {LINKTYPE => ''},
	'dist' => {COMPRESS => 'gzip', SUFFIX => 'gz'},
	$] >= 5.005 ? (
		AUTHOR => 'Tom Wyant (Thomas.R.Wyant-III@usa.dupont.com)',
		ABSTRACT => 'Get information on arbitrary processes in Windows NT',
		BINARY_LOCATION => "$Config{archname}$vers/Win32-Process-Info.tar.gz",
		) : (),
	);

