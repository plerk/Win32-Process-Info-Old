use Config;
use ExtUtils::MakeMaker;

WriteMakefile (
	NAME => 'Win32::Process::Info',
	VERSION_FROM => 'Info.pm',
	PREREQ_PM => {'Win32' => 0.18,
			'Win32::API' => 0.01,
			'Win32::OLE' => 0.1502,
			'Win32API::Registry' => 0.22,
			},
#	'linkext' => {LINKTYPE => ''},
	'dist' => {COMPRESS => 'gzip', SUFFIX => 'gz'},
	$] >= 5.005 ? (
		AUTHOR => 'Tom Wyant (Thomas.R.Wyant-III@usa.dupont.com)',
		ABSTRACT => 'Get information on arbitrary processes in Windows NT',
		BINARY_LOCATION => "$Config{archname}/Win32-Process-Info.tar.gz",
		) : (),
	);

