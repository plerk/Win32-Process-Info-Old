use Config;
use ExtUtils::MakeMaker;

my $vers = $] >= 5.008 ? '-5.8' : '';

WriteMakefile (
	NAME => 'Win32::Process::Info',
	VERSION_FROM => 'Info.pm',
	PREREQ_PM => {
##1.001			'Win32' => 0.18,
##0.013			'Win32::API' => 0.01,
##0.013			'Win32::OLE' => 0.1502,
##0.013			'Win32API::Registry' => 0.22,
			},
#	'linkext' => {LINKTYPE => ''},
	'dist' => {COMPRESS => 'gzip', SUFFIX => 'gz'},
	$] >= 5.005 ? (
		AUTHOR => 'Tom Wyant (Thomas.R.Wyant-III@usa.dupont.com)',
		ABSTRACT => 'Get information on arbitrary processes in Windows NT',
		BINARY_LOCATION => "$Config{archname}$vers/Win32-Process-Info.tar.gz",
		) : (),
	);

