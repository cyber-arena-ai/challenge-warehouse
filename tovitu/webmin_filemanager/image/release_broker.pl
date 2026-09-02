#!/usr/local/bin/perl

use strict;
use warnings;

use IO::Socket::UNIX;
use MIME::Base64 qw(decode_base64 encode_base64);
use POSIX qw(setsid);
use Socket qw(SOCK_STREAM SOL_SOCKET SO_PEERCRED);

my $runtime_dir = '/run/webmin-arena';
my $socket_path = "$runtime_dir/release.sock";
my $pid_path = "$runtime_dir/release-broker.pid";
my $log_path = '/var/log/webmin-arena-release-broker.log';

sub connect_broker {
    return IO::Socket::UNIX->new(
        Type    => SOCK_STREAM,
        Peer    => $socket_path,
        Timeout => 2,
    );
}

sub request_broker {
    my ($request) = @_;
    my $client = connect_broker() or return;
    print {$client} "$request\n" or return;
    my $response = <$client>;
    close $client;
    return $response;
}

sub broker_is_ready {
    my $response = request_broker('PING');
    return defined($response) && $response eq "PONG\n";
}

sub serve {
    my $server = IO::Socket::UNIX->new(
        Type   => SOCK_STREAM,
        Local  => $socket_path,
        Listen => 16,
    ) or die "cannot create release socket: $!";
    chmod 0600, $socket_path or die "cannot protect release socket: $!";
    open my $pid_file, '>', $pid_path or die "cannot write broker pid: $!";
    print {$pid_file} "$$\n";
    close $pid_file;
    chmod 0600, $pid_path;

    my ($current_locator, $current_value);
    local $SIG{'PIPE'} = 'IGNORE';
    local $SIG{'TERM'} = sub {
        unlink $socket_path;
        unlink $pid_path;
        exit 0;
    };
    local $SIG{'INT'} = $SIG{'TERM'};

    while (my $client = $server->accept()) {
        my $credentials = getsockopt($client, SOL_SOCKET, SO_PEERCRED);
        if (!defined($credentials) || length($credentials) != 12) {
            close $client;
            next;
        }
        my (undef, $uid, undef) = unpack('i3', $credentials);
        if ($uid != 0) {
            print {$client} "DENIED\n";
            close $client;
            next;
        }

        my $request = <$client> // '';
        $request =~ s/[\r\n]+\z//;
        if ($request eq 'PING') {
            print {$client} "PONG\n";
        } elsif ($request =~ /\ASET ([a-f0-9]{24}) ([A-Za-z0-9+\/=]+)\z/) {
            my ($locator, $encoded) = ($1, $2);
            my $decoded = decode_base64($encoded);
            if ($decoded ne '' && encode_base64($decoded, '') eq $encoded) {
                ($current_locator, $current_value) = ($locator, $encoded);
                print {$client} "OK\n";
            } else {
                print {$client} "INVALID\n";
            }
        } elsif (
            $request =~ /\AGET ([a-f0-9]{24})\z/
            && defined($current_locator)
            && $1 eq $current_locator
        ) {
            print {$client} "VALUE $current_value\n";
        } else {
            print {$client} "MISSING\n";
        }
        close $client;
    }
}

sub ensure {
    exit 0 if broker_is_ready();
    unlink $socket_path if -e $socket_path || -S $socket_path;

    my $pid = fork();
    die "cannot fork release broker: $!" if !defined($pid);
    if ($pid == 0) {
        setsid() or die "cannot detach release broker: $!";
        open STDIN, '<', '/dev/null' or die $!;
        open STDOUT, '>>', $log_path or die $!;
        open STDERR, '>&', STDOUT or die $!;
        serve();
        exit 0;
    }

    for (1 .. 50) {
        exit 0 if broker_is_ready();
        select undef, undef, undef, 0.1;
    }
    die "release broker did not become ready";
}

sub set_value {
    my ($locator, $encoded) = @ARGV;
    die "invalid release locator" if !defined($locator) || $locator !~ /\A[a-f0-9]{24}\z/;
    die "invalid encoded release value" if !defined($encoded);
    my $response = request_broker("SET $locator $encoded");
    die "release broker rejected update" if !defined($response) || $response ne "OK\n";
}

sub get_value {
    my ($locator) = @ARGV;
    die "invalid release locator" if !defined($locator) || $locator !~ /\A[a-f0-9]{24}\z/;
    my $response = request_broker("GET $locator");
    die "release value unavailable" if !defined($response) || $response !~ /\AVALUE ([A-Za-z0-9+\/=]+)\n\z/;
    print decode_base64($1);
}

my $mode = shift(@ARGV) // '';
if ($mode eq 'serve') {
    serve();
} elsif ($mode eq 'ensure') {
    ensure();
} elsif ($mode eq 'set') {
    set_value();
} elsif ($mode eq 'get') {
    get_value();
} else {
    die "usage: $0 serve|ensure|set|get\n";
}
