package Test::Nginx::OIDC;

# Copyright (c) F5, Inc.
#
# This source code is licensed under the Apache License, Version 2.0 license
# found in the LICENSE file in the root directory of this source tree.

# Module for NJS OIDC tests.

###############################################################################

use warnings;
use strict;

use IO::Select;
use IO::Socket::INET;
use Socket qw/CRLF/;

use Digest::SHA qw/hmac_sha256/;
use JSON::PP qw/decode_json encode_json/;
use MIME::Base64 qw/encode_base64/;
use Test::Nginx qw/http/;

use Exporter 'import';
our @EXPORT_OK = qw/
    parse_response
    build_code_request
    idp_socket
    idp_daemon
    set_state
    get_state
/;

our $port;
my $authorization_code = 'aaaa';

###############################################################################

sub parse_response {
    my ($raw) = @_;
    return unless defined $raw && length $raw;

    my %r = (res => $raw);

    if ($raw =~ /^HTTP\/\d+\.\d+\s+(\d{3})/) {
        $r{status} = $1;
    }

    while ($raw =~ /^([^:\s]+):\s*([^\r\n]+)/gmi) {
        my ($h, $v) = (lc $1, $2);
        push @{ $r{headers}{$h} }, $v;
        if ($h eq 'location') {
            $r{location} = $v;
        } elsif ($h eq 'set-cookie' && !exists $r{cookie}) {
            $r{cookie} = $v;
        }
    }

    my $loc = $r{location} // '';
    if ($loc =~ /\?(.+)/) {
        for my $kv (split /[&;]/, $1) {
            my ($k, $v) = split /=/, $kv, 2;
            next unless defined $k;
            $v //= '';
            $k =~ tr/+/ /;
            $v =~ tr/+/ /;
            $k =~ s/%([0-9A-Fa-f]{2})/chr hex $1/eg;
            $v =~ s/%([0-9A-Fa-f]{2})/chr hex $1/eg;
            $r{$k} = $v;
        }
    }

    return \%r;
}

###############################################################################

sub idp_socket {
    IO::Socket::INET->new(
        Proto    => 'tcp',
        PeerAddr => "127.0.0.1:$port",
    ) or die "Can't connect to mock IdP at 127.0.0.1:$port: $!\n";
}

sub build_code_request {
    my ($flow, %opt) = @_;

    my ($host, $path) = ($flow->{redirect_uri} // '') =~ m{^https?://([^/]+)(/.*)$}
        or die "Unsupported redirect_uri in flow\n";

    my %q = (
        state => $flow->{state},
        code  => ($opt{code} // $authorization_code),
        (defined $opt{session_state} ? (session_state => $opt{session_state}) : ()),
        %{ $opt{extra} // {} },
    );
    delete @q{ @{ $opt{omit} // [] } };

    my $qs = join '&', map { "$_=$q{$_}" } sort keys %q;
    my $uri = $path . ($qs ne '' ? "?$qs" : '');

    my $cookie = defined $opt{cookie} ? $opt{cookie} : _cookie_header($flow);
    my $r = "GET $uri HTTP/1.0" . CRLF
          . "Host: $host" . CRLF
          . "Connection: close" . CRLF;

    $r .= "Cookie: $cookie" . CRLF if $cookie ne '';
    $r .= CRLF;

    return $r;
}

sub _cookie_header {
    my ($flow) = @_;

    my $set_cookie = $flow->{headers}{'set-cookie'} || [];
    if (@$set_cookie) {
        my @cookies = map {
            my ($kv) = split /;/, ($_ // ''), 2;
            $kv;
        } @$set_cookie;
        @cookies = grep { defined $_ && $_ ne '' } @cookies;
        return join '; ', @cookies;
    }

    my ($kv) = split /;/, ($flow->{cookie} // ''), 2;
    return $kv // '';
}

sub set_state {
    my %params = @_;
    my $body = join '&', map { "$_=$params{$_}" } keys %params;
    _http_post('/set-state', $body, socket => idp_socket());
}

sub get_state {
    my $response = _http_get('/get-state', socket => idp_socket());
    my (undef, $body) = split /\r?\n\r?\n/, $response, 2;
    return decode_json($body);
}

sub _http_get {
    my ($url, %args) = @_;
    my $req = "GET $url HTTP/1.0" . CRLF
            . "Host: localhost" . CRLF
            . "Connection: close" . CRLF
            . CRLF;
    return http($req, %args);
}

sub _http_post {
    my ($url, $body, %args) = @_;
    my $req = "POST $url HTTP/1.0" . CRLF
            . "Host: localhost" . CRLF
            . "Connection: close" . CRLF
            . "Content-Length: " . length($body) . CRLF
            . CRLF
            . $body;
    return http($req, %args);
}

###############################################################################

sub idp_daemon {
    my ($issuer, $client_id, $jwt_secret) = @_;

    my $server = IO::Socket::INET->new(
        Proto     => 'tcp',
        LocalAddr => '127.0.0.1',
        LocalPort => $port,
        Listen    => 128,
        Reuse     => 1,
    ) or die "Can't create mock IdP listening socket: $!\n";

    my $state = {
        issuer        => $issuer,
        client_id     => $client_id,
        jwt_secret    => $jwt_secret,
        jwt_kid       => 'test-kid',
        nonce         => undef,
        code_seq      => 0,
        codes         => {},
        token_hits    => 0,
        id_token      => undef,
        access_token  => undef,
        refresh_token => undef,
        requests      => {},
    };

    my $sel = IO::Select->new($server);

    while (my @ready = $sel->can_read()) {
        foreach my $s (@ready) {
            if ($s == $server) {
                my $c = $server->accept();
                $sel->add($c) if $c;
                next;
            }

            if (!$s->connected) {
                $sel->remove($s);
                $s->close();
                delete $state->{requests}{$s};
                next;
            }

            my ($method, $uri, $body) = _read_request($s, $state);
            next unless defined $uri;

            _route_request($s, $method, $uri, $body, $state);

            $sel->remove($s);
            $s->close();
            delete $state->{requests}{$s};
        }
    }
}

sub _read_request {
    my ($client, $state) = @_;

    $state->{requests}{$client} = '' unless exists $state->{requests}{$client};
    $state->{requests}{$client} .= $_ if $client->sysread($_, 65536);

    return unless $state->{requests}{$client} =~ m/^\r?\n/mg;

    my $cl = 0;
    $cl = $1 if $state->{requests}{$client} =~ /^content-length:\s*([0-9]+)/mi;

    return if $cl + pos($state->{requests}{$client}) > length($state->{requests}{$client});

    my $body = '';
    $body = substr($state->{requests}{$client}, pos($state->{requests}{$client}), $cl) if $cl > 0;

    my $method = $1 if $state->{requests}{$client} =~ /^(\S+)\s+/;
    my $uri    = $1 if $state->{requests}{$client} =~ /^\S+\s+([^ ]+)\s+HTTP/i;

    return ($method, $uri, $body);
}

sub _route_request {
    my ($client, $method, $uri, $body, $state) = @_;

    my ($path, $query) = split /\?/, ($uri // ''), 2;
    $query //= '';

    if ($path eq '/auth') {
        _handle_auth($client, $query, $state);
        return;
    }

    if ($path eq '/set-state') {
        _handle_set_state($client, $body, $state);
        return;
    }

    if ($path eq '/get-state') {
        _handle_get_state($client, $state);
        return;
    }

    if ($path eq '/token') {
        _handle_token($client, $body, $state);
        return;
    }

    if ($path eq '/certs') {
        _handle_keys($client, $state);
        return;
    }

    _send_response($client, 404, "not found\n", {
        'Content-Type' => 'text/plain',
        'Connection'   => 'close',
    });
}

sub _handle_auth {
    my ($client, $query, $state) = @_;

    my %p = _parse_params($query);

    my $redirect_uri = $p{redirect_uri} // '';
    my $nonce        = $p{nonce}        // '';
    my $state_param  = defined $p{state} ? $p{state} : '0';

    $state->{nonce} = $nonce;

    my $code = sprintf("code%04d", ++$state->{code_seq});

    $state->{codes}{$code} = {
        nonce        => $nonce,
        redirect_uri => $redirect_uri,
        state        => $state_param,
    };

    my $sep = ($redirect_uri =~ /\?/) ? '&' : '?';
    my $location = $redirect_uri . $sep . "code=$code&state=$state_param";

    _send_response($client, 302, '', {
        'Location'      => $location,
        'Cache-Control' => 'no-store',
        'Connection'    => 'close',
    });
}

sub _handle_set_state {
    my ($client, $body, $state) = @_;
    my %p = _parse_params($body);

    foreach my $k (keys %p) {
        next if $k eq 'requests' || $k eq 'codes';
        next unless exists $state->{$k};
        $state->{$k} = $p{$k};
    }

    _send_response($client, 204, '', {
        'Connection' => 'close',
    });
}

sub _handle_get_state {
    my ($client, $state) = @_;

    my %public = %$state;
    delete $public{requests};
    delete $public{codes};

    _send_response($client, 200, encode_json(\%public), {
        'Content-Type' => 'application/json',
        'Connection'   => 'close',
    });
}

sub _handle_token {
    my ($client, $body, $state) = @_;

    $state->{token_hits}++;

    my %p = _parse_params($body);
    my $grant_type = $p{grant_type} // '';

    if ($grant_type eq 'authorization_code') {
        my $code = $p{code} // '';
        my $rec  = $state->{codes}{$code};

        unless ($rec || $code eq $authorization_code) {
            _send_response($client, 400, encode_json({
                error             => 'invalid_grant',
                error_description => 'unknown code',
            }), {
                'Content-Type' => 'application/json',
                'Connection'   => 'close',
            });
            return;
        }

        my $now = time();

        my %claims = (
            iss   => $state->{issuer},
            sub   => 'user1',
            aud   => $state->{client_id},
            iat   => $now,
            exp   => $now + 3600,
            nonce => (defined $state->{nonce} ? $state->{nonce} : ($rec->{nonce} // '')),
            sid   => 'sid1',
        );

        my $id_token = _encode_jwt_hs256(\%claims, $state->{jwt_secret}, $state->{jwt_kid});

        my $access_token  = _random_token();
        my $refresh_token = _random_token();
        $state->{id_token} = $id_token;
        $state->{access_token} = $access_token;
        $state->{refresh_token} = $refresh_token;

        my $resp = encode_json({
            token_type    => 'Bearer',
            expires_in    => 3600,
            access_token  => $access_token,
            refresh_token => $refresh_token,
            id_token      => $id_token,
        });

        _send_response($client, 200, $resp, {
            'Content-Type'  => 'application/json',
            'Cache-Control' => 'no-store',
            'Connection'    => 'close',
        });

        return;
    }

    if ($grant_type eq 'refresh_token') {
        my $rt = $p{refresh_token} // '';
        if (!$state->{refresh_token} || $rt ne $state->{refresh_token}) {
            _send_response($client, 400, encode_json({
                error             => 'invalid_grant',
                error_description => 'invalid refresh_token',
            }), {
                'Content-Type' => 'application/json',
                'Connection'   => 'close',
            });
            return;
        }

        my $now = time();

        my %claims = (
            iss => $state->{issuer},
            sub => 'user1',
            aud => $state->{client_id},
            iat => $now,
            exp => $now + 3600,
            sid => 'sid1',
        );

        my $id_token = _encode_jwt_hs256(\%claims, $state->{jwt_secret}, $state->{jwt_kid});

        my $access_token = _random_token();
        $state->{id_token} = $id_token;
        $state->{access_token} = $access_token;

        my $resp = encode_json({
            token_type    => 'Bearer',
            expires_in    => 3600,
            access_token  => $access_token,
            id_token      => $id_token,
        });

        _send_response($client, 200, $resp, {
            'Content-Type'  => 'application/json',
            'Cache-Control' => 'no-store',
            'Connection'    => 'close',
        });

        return;
    }

    _send_response($client, 400, encode_json({
        error             => 'unsupported_grant_type',
        error_description => "grant_type=$grant_type",
    }), {
        'Content-Type' => 'application/json',
        'Connection'   => 'close',
    });
}

sub _handle_keys {
    my ($client, $state) = @_;

    my $jwks = encode_json({
        keys => [ {
            kty => 'oct',
            kid => $state->{jwt_kid},
            use => 'sig',
            alg => 'HS256',
            k   => _b64url($state->{jwt_secret}),
        } ],
    });

    _send_response($client, 200, $jwks, {
        'Content-Type'  => 'application/json',
        'Cache-Control' => 'max-age=3600',
        'Connection'    => 'close',
    });
}

sub _send_response {
    my ($client, $status, $body, $headers) = @_;

    $body ||= '';
    $headers ||= {};

    my $status_text = {
        200 => 'OK',
        302 => 'Found',
        400 => 'Bad Request',
        404 => 'Not Found',
    }->{$status} || 'OK';

    print $client "HTTP/1.1 $status $status_text" . CRLF;

    $headers->{'Content-Length'} = length($body)
        if !exists $headers->{'Content-Length'};

    foreach my $h (keys %$headers) {
        print $client "$h: $headers->{$h}" . CRLF;
    }

    print $client CRLF . $body;
}

sub _parse_params {
    my ($query) = @_;
    my %params;

    foreach my $pair (split /&/, ($query // '')) {
        next if $pair eq '';
        my ($key, $value) = split /=/, $pair, 2;
        $value //= '';
        $key =~ tr/+/ /;
        $value =~ tr/+/ /;
        $key =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        $value =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/eg;
        $params{$key} = $value;
    }

    return %params;
}

sub _encode_jwt_hs256 {
    my ($claims, $secret, $kid) = @_;

    my $header = {
        typ => 'JWT',
        alg => 'HS256',
        kid => $kid,
    };

    my $h64 = _b64url(encode_json($header));
    my $p64 = _b64url(encode_json($claims));

    my $data = "$h64.$p64";
    my $sig  = hmac_sha256($data, $secret);

    return $data . '.' . _b64url($sig);
}

sub _b64url {
    my ($raw) = @_;
    my $b64 = encode_base64($raw, '');
    $b64 =~ tr|+/|-_|;
    $b64 =~ s/=+$//;
    return $b64;
}

sub _random_token {
    my @chars = ('a'..'z', 'A'..'Z', '0'..'9', '-', '_');
    return join '', map { $chars[rand @chars] } 1..32;
}

###############################################################################

1;

###############################################################################
