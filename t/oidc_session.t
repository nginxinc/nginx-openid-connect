#!/usr/bin/perl

# (C) Ivan Ovchinnikov
# (C) Nginx, Inc.

# Tests for njs-based OIDC SSO solution.

###############################################################################

use warnings;
use strict;

use Test::More;

BEGIN { use FindBin; chdir($FindBin::Bin); }

use lib 'lib';

use Test::Nginx;

use Test::Nginx::OIDC qw/
    parse_response
    build_code_request
    idp_socket
    idp_daemon
    set_state
    get_state
/;

###############################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require JSON::PP; };
plan(skip_all => "JSON::PP not installed") if $@;

my $idp_port   = port(8082);
my $client_id  = 'test-client';
my $jwt_secret = 'test-jwt-secret';
my $issuer     = "http://127.0.0.1:$idp_port";

my $t = Test::Nginx->new()->has(qw/http/)->plan(21);
my $d = $t->testdir();

###############################################################################
# Copy the OIDC-related files into the test prefix.

my $root = "$FindBin::Bin/..";

sub slurp {
    my ($path) = @_;
    open my $fh, '<', $path or die "Can't open $path: $!\n";
    local $/;
    return <$fh>;
}

$t->write_file('openid_connect.js', slurp("$root/openid_connect.js"));
$t->write_file('openid_connect.server_conf', slurp("$root/openid_connect.server_conf"));

###############################################################################

my $conf = <<'EOF';
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path jwk levels=1 keys_zone=jwk:64k max_size=1m;

    keyval_zone zone=oidc_id_tokens:1M     state=oidc_id_tokens.json     timeout=1h;
    keyval_zone zone=oidc_access_tokens:1M state=oidc_access_tokens.json timeout=1h;
    keyval_zone zone=refresh_tokens:1M     state=refresh_tokens.json     timeout=8h;
    keyval_zone zone=oidc_sids:1M          state=oidc_sids.json          timeout=8h;
    keyval_zone zone=oidc_pkce:128k timeout=90s;

    keyval $cookie_auth_token $session_jwt     zone=oidc_id_tokens;
    keyval $cookie_auth_token $access_token    zone=oidc_access_tokens;
    keyval $cookie_auth_token $refresh_token   zone=refresh_tokens;

    keyval $request_id $new_session            zone=oidc_id_tokens;
    keyval $request_id $new_access_token       zone=oidc_access_tokens;
    keyval $request_id $new_refresh            zone=refresh_tokens;

    keyval $pkce_id $pkce_code_verifier        zone=oidc_pkce;
    keyval $idp_sid $client_sid                zone=oidc_sids;

    auth_jwt_claim_set $jwt_audience aud;

    js_import oidc from openid_connect.js;

    map $http_x_forwarded_proto $proto {
        ""      $scheme;
        default $http_x_forwarded_proto;
    }

    map $http_x_forwarded_port $redirect_base {
        ""      $proto://$host:$server_port;
        default $proto://$host:$http_x_forwarded_port;
    }

    map $proto $oidc_cookie_flags {
        http  "Path=/; SameSite=lax;";
        https "Path=/; SameSite=lax; HttpOnly; Secure;";
    }

    server {
        listen 127.0.0.1:8080;
        server_name localhost;

        auth_jwt_key_request /_jwks_uri;

        set $oidc_authz_endpoint "http://127.0.0.1:%%IDP_PORT%%/auth";
        set $oidc_authz_extra_args "";
        set $oidc_token_endpoint "http://127.0.0.1:%%IDP_PORT%%/token";
        set $oidc_jwt_keyfile "http://127.0.0.1:%%IDP_PORT%%/certs";
        set $oidc_end_session_endpoint "";

        set $oidc_client "%%CLIENT_ID%%";
        set $oidc_client_secret "test-client-secret";
        set $oidc_client_auth_method "client_secret_post";
        set $oidc_scopes "openid";
        set $oidc_hmac_key "test-hmac-key";
        set $oidc_pkce_enable 0;

        set $zone_sync_leeway 0;

        include openid_connect.server_conf;

        location = / {
            auth_jwt "" token=$session_jwt;
            error_page 401 = @do_oidc_flow;

            add_header X-Test-AT "$access_token";
            add_header X-Test-ID "$session_jwt";
            add_header X-Test-ISS "$jwt_claim_iss";

            proxy_pass http://127.0.0.1:8081;
        }
    }

    server {
        listen       127.0.0.1:8081;
        server_name  localhost;

        location / {
            return 200 "FOO";
        }
    }
}
EOF

$conf =~ s/%%TESTDIR%%/$d/g;
$conf =~ s/%%IDP_PORT%%/$idp_port/g;
$conf =~ s/%%CLIENT_ID%%/$client_id/g;

$t->write_file_expand('nginx.conf', $conf);

$Test::Nginx::OIDC::port = $idp_port;
$t->run_daemon(\&idp_daemon, $issuer, $client_id, $jwt_secret)
    ->waitforsocket('127.0.0.1:' . $idp_port);

$t->run();

my $api_version = (sort { $a <=> $b } @{ api('/api/') })[-1];

###############################################################################

my $flow = parse_response(http_get('/'));

like($flow->{location}, qr/^\Q$issuer\E\/auth\?/, 'redirect to idp');

is($flow->{response_type}, 'code', 'response_type');
is($flow->{scope}, 'openid', 'default scope');

ok(defined $flow->{state} && defined $flow->{nonce}, 'state and nonce are set');
is($flow->{client_id}, $client_id, 'client_id');

like($flow->{redirect_uri}, qr!^https?://localhost:8080/_codexch$!, 
    'callback uri');

my $set_cookie = join "\n", @{ $flow->{headers}{'set-cookie'} };
like($set_cookie, qr/\bauth_redir=%2F;/, 'auth_redir is set');
like($set_cookie, qr/\bauth_nonce=[0-9a-f]{32};/i, 'auth_nonce is set');

set_state(nonce => $flow->{nonce});

$flow = http(build_code_request($flow));
$flow = parse_response($flow);

like($flow->{cookie}, qr/^auth_token=[^;]+;/, 'session cookie auth_token');
like($flow->{location}, qr!^http://localhost(?::\d+)?/(?:\?.*)?$!,
    'redirect to original url'
);

my $cookie = $flow->{cookie};
my $r = http_get_auth('/', $cookie);
my $st = get_state();

like($r, qr/FOO/, 'access granted');
like($r, qr/X-Test-AT: \Q$st->{access_token}\E/s, 'access token variable');
like($r, qr/X-Test-ID: \Q$st->{id_token}\E/s, 'id token variable');
like($r, qr/X-Test-ISS: \Q$issuer\E/s, 'iss claim variable');
is($st->{token_hits}, 1, '1 tokenset request');

my ($session_id) = $flow->{cookie} =~ /^auth_token=([^;]+)/;
is(get_kv('oidc_id_tokens')->{$session_id}, $st->{id_token}, 'kv id_token');
is(get_kv('oidc_access_tokens')->{$session_id}, $st->{access_token},
    'kv access_token');
is(get_kv('refresh_tokens')->{$session_id}, $st->{refresh_token},
    'kv refresh_token');
is(get_kv('oidc_sids')->{sid1}, $session_id, 'kv sid to session id');
is_deeply(get_kv('oidc_pkce'), {}, 'kv pkce is empty with pkce disabled');

del_kv('/http/keyvals/oidc_id_tokens');
like(http_get_auth('/', $cookie), qr/FOO/, 'session refreshed');

# ###############################################################################

sub http_get_auth {
    my ($url, $cookie) = @_;
    return http(<<EOF);
GET $url HTTP/1.0
Host: localhost
Cookie: $cookie

EOF
}

sub api {
    http_get(shift) =~ /\x0d\x0a?\x0d\x0a?(.*)/ms;
    return eval $1;
}

sub get_kv {
    my ($zone) = @_;
    my $r = http_get("/api/$api_version/http/keyvals/$zone");
    $r =~ /\x0d\x0a?\x0d\x0a?(.*)/ms;
    return JSON::PP::decode_json($1);
}

sub del_kv {
    my ($url) = @_;
    return http(<<EOF);
DELETE /api/$api_version$url HTTP/1.1
Host: localhost
Connection: close

EOF
}

###############################################################################
