use ExtUtils::MakeMaker;

sub MY::postamble {
    my $string = <<EOF;

install::

\tinstall -m 755 etc/init.d/npsnortd /etc/init.d/npsnortd
\tinstall -m 600 etc/sysconfig/npsnortd /etc/sysconfig/npsnortd
\tinstall -m 600 etc/sysconfig/snort /etc/sysconfig/snort

EOF
}

WriteMakefile(
    'NAME'         => 'NetPass::Snort',
    'VERSION_FROM' => 'lib/NetPass/Snort.pm',
    'EXE_FILES'    => [ 'bin/npsnortd.pl' ],
    'PREREQ_PM' => { 'SOAP::Lite' 	    => '0.60',
                     'SOAP::Transport::TCP' => 'v1.0.0',
                     'Sys::HostIP'          => '1.0',
                     'File::Tail'           => '0.99.1',
                   },
    'dist'         => { 'SUFFIX'       => ".gz",
                        'DIST_DEFAULT' => 'all tardist',
                        'COMPRESS'     => "gzip -9f" },
    'realclean'    => { 'FILES' => '' },
    'clean'        => { 'FILES' => '' },
);
