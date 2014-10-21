use 5.006;
use strict;
use warnings FATAL => 'all';
use ExtUtils::MakeMaker;

WriteMakefile(
    NAME             => 'Net::Joker::DMAPI',
    AUTHOR           => q{David Precious <davidp@preshweb.co.uk>},
    VERSION_FROM     => 'lib/Net/Joker/DMAPI.pm',
    ABSTRACT_FROM    => 'lib/Net/Joker/DMAPI.pm',
    LICENSE          => 'Artistic_2_0',
    PL_FILES         => {},
    MIN_PERL_VERSION => 5.010,
    CONFIGURE_REQUIRES => {
        'ExtUtils::MakeMaker' => 0,
    },
    BUILD_REQUIRES => {
        'Test::More' => 0,
    },
    PREREQ_PM => {
        'Data::Censor'   => 0,
        'DateTime'       => 0,
        'Hash::Merge'    => 0,
        'LWP::UserAgent' => 0,
        'Moose'          => 0,
        URI              => 0,
    },
    dist  => { COMPRESS => 'gzip -9f', SUFFIX => 'gz', },
    clean => { FILES => 'Net-Joker-DMAPI-*' },
);
