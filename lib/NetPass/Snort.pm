package NetPass::Snort;

=head1 NAME

NetPass::Snort - NetPass Snort API

=head1 SYNOPSIS

    use NetPass::Snort;

=head1 DESCRIPTION

This is the NetPass::Snort which is the netpass interface
to the snort daemon through SOAP API calls. This package
should only be used in conjunction with npsoapd.pl.

=head1 METHODS

=cut


use strict;
use Digest::MD5 qw(md5_hex);
use SOAP::Lite;
use Sys::HostIP;
use Sys::Hostname;
use FileHandle;
use File::Copy "move";

use vars qw($VERSION);
$VERSION = '2.00';

my $DEFAULTSNORTRULES   = "/opt/snort/etc/snort.rules";
my $DEFAULTSNORTBPF     = "/opt/snort/etc/pcaprules.txt";
my $DEFAULTSNORTPID	= "/var/run/snort_dag0.pid";
my $DEFAULTSNORTCMD     = "/etc/init.d/snortd";

# make sure this matches DEFAULTPORT in npsnortd.pl
my $DEFAULTPORT         = 20008;

my $check_soap_auth = sub {
        my $self         = shift;
        my $their_secret = shift;
        my $rip          = $::remote_ip;
        my %opts         = %::opts;

	return 0 unless defined $rip && exists $opts{'S'};
        my $my_secret    = md5_hex($rip.$opts{'S'});

        return ($their_secret eq $my_secret) ? 1 : 0;
};

my $update_pcap_rules_file = sub {
	my $self        = shift;
	my $secret	= shift;
	my $soap	= shift;
        my %opts        = %::opts;
        my $fh          = new FileHandle;

	my $sensor = join(':', hostname, ((exists $opts{'P'}) ? $opts{'P'} : $DEFAULTPORT));
        my $pcaprules   = eval {$soap->getSnortPCAPFilter(
                                              		  -secret	=> $secret,
							  -sensor	=> $sensor,
							  -ignorequar   => (exists $opts{'q'}) ? 1 : 0
                                             		 )->result};
        return undef if $pcaprules eq "";

        my $rulesfile = (exists $opts{'b'}) ? $opts{'b'} : $DEFAULTSNORTBPF;

        # create a backup copy of the rules file
        move($rulesfile, $rulesfile.'.bkp') if (-e $rulesfile);

        $fh->open("> $rulesfile");
        print $fh $pcaprules."\n";
        $fh->close;

	return 1;
};

my $snortGetPid = sub {
        my %opts = %::opts;
        my $fh   = new FileHandle;

	my $pidfile = (exists $opts{'p'}) ? $opts{'p'} : $DEFAULTSNORTPID;

        if (-e $pidfile && $fh->open($pidfile)) {
                my $pid = <$fh>;
                chomp $pid;
                $fh->close;
                return $pid;
        }

        return undef;
};

my $snortRunning = sub {
        my $self = shift;

        my $pid = $self->$snortGetPid();
        return undef unless $pid;

        return 1 if (kill(0, $pid) > 0);
        return undef;
};

my $createSoapConnection = sub {
        my %opts = %::opts;

	return undef unless exists $opts{'s'};
        foreach my $server (split(/\,/, $opts{'s'})) {
                my $proxy = "tcp://$server:20003";
                my $soap  = SOAP::Lite->new(
                                            uri   => 'tcp://netpass/NetPass/API',
                                            proxy => $proxy,
                                           );
                return undef unless defined $soap;

                # check to make sure we have a good connection
                my $rv = eval {$soap->echo()->result};
                return $soap if $rv;
        }

        return undef;
};

=head2 $rv = startSnort()

This method starts the snort daemon, it returns C<true> on 
success C<undef> on failure.

=cut

sub startSnort {
	my $self	= shift;
	my $key		= shift;
	my %opts        = %::opts;
        my $fh          = new FileHandle;

	return undef unless ($self->$check_soap_auth($key));
        return undef unless exists $opts{'S'};
        my $md5         = md5_hex(hostip.$opts{'S'});

        my $soap = $self->$createSoapConnection();
        return undef unless $soap;

        my $aref = eval {$soap->getSnortRules(
					      -secret 	      => $md5,
					      -type           => "enabled",
					     )->result};
        return undef unless defined($aref) && (ref($aref) eq 'ARRAY');

        my $rulesfile = (exists $opts{'r'}) ? $opts{'r'} : $DEFAULTSNORTRULES;

        # create a backup copy of the rules file
        move($rulesfile, $rulesfile.'.bkp') if (-e $rulesfile);

        $fh->open("> $rulesfile");
        foreach my $l (@$aref) {
                chomp $l;
		$l =~ s/\r\n/ /g;
                print $fh $l."\n";
        }
        $fh->close;

	$self->$update_pcap_rules_file($md5, $soap);

	my $cmd = (exists $opts{'f'}) ? $opts{'f'} : $DEFAULTSNORTCMD;
	return undef unless -e $cmd;

	my $rv = system("$cmd start");
	return undef unless defined $rv;

	return $self->$snortRunning();
}

=head2 $rv = stopSnort()

This method stops the snort daemon, it returns C<true> on
success C<undef> on failure.

=cut

sub stopSnort {
        my $self        = shift;
        my $key         = shift;
        my %opts        = %::opts;

        return undef unless ($self->$check_soap_auth($key));

        my $cmd = (exists $opts{'f'}) ? $opts{'f'} : $DEFAULTSNORTCMD;
        return undef unless -e $cmd;

        my $rv = system("$cmd stop");
        return $rv;
}

=head2 $rv = restartSnort()

This method checks to see if the snort daemon is running and
restarts the daemon. It also reloads the rules from the
NetPass database. Returns C<true> on success,
C<undef> on failure.

=cut


sub restartSnort {
        my $self         = shift;
        my $key          = shift;
        my %opts         = %::opts;
        my $fh           = new FileHandle;

	return undef unless exists $opts{'S'};
        my $md5          = md5_hex(hostip.$opts{'S'});

        return undef unless ($self->$check_soap_auth($key));
        return undef unless ($self->$snortRunning());

        my $pid = $self->$snortGetPid();
        return undef unless $pid;

        my $soap = $self->$createSoapConnection();
        return undef unless $soap;

        my $aref = eval {$soap->getSnortRules(
                                              -secret         => $md5,
                                              -type           => "enabled",
                                             )->result};
        return undef unless defined($aref) && (ref($aref) eq 'ARRAY');

	my $rulesfile = (exists $opts{'r'}) ? $opts{'r'} : $DEFAULTSNORTRULES;

	# create a backup copy of the rules file
	move($rulesfile, $rulesfile.'.bkp') if (-e $rulesfile);

	$fh->open("> $rulesfile");
        foreach my $l (@$aref) {
                chomp $l;
		$l =~ s/\r\n/ /g;
                print $fh $l."\n";
        }
	$fh->close;

	$self->$update_pcap_rules_file($md5, $soap);
		
        return 1 if (kill('HUP', $pid) > 0);
        return undef;
}

=head2 $rv = snortStatus()

This method checks to see if the snort daemon is running.
Returns C<true> on success, C<undef> on failure.

=cut

sub snortStatus {
        my $self = shift;
        my $key  = shift;

        return $self->$snortRunning() if ($self->$check_soap_auth($key));
        return undef;
}

=head2 echo()

Used to determine if we have a valid connection, Returns 1 always.

=cut

sub echo {1}

1;

