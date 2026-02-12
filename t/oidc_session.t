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

$t->write_file_expand('nginx.conf', <<'EOF');
%%TEST_GLOBALS%%

daemon off;

events {
}

http {
    %%TEST_GLOBALS_HTTP%%

    proxy_cache_path jwk levels=1 keys_zone=jwk:32k max_size=1m;

    keyval_zone zone=oidc_authz_endpoint:32k;
    keyval_zone zone=oidc_authz_extra_args:32k;
    keyval_zone zone=oidc_token_endpoint:32k;
    keyval_zone zone=oidc_jwt_keyfile:32k;
    keyval_zone zone=oidc_end_session_endpoint:32k;
    keyval_zone zone=oidc_client:32k;
    keyval_zone zone=oidc_pkce_enable:32k;
    keyval_zone zone=oidc_client_secret:32k;
    keyval_zone zone=oidc_client_auth_method:32k;
    keyval_zone zone=oidc_scopes:32k;
    keyval_zone zone=oidc_logout_redirect:32k;
    keyval_zone zone=oidc_hmac_key:32k;
    keyval_zone zone=zone_sync_leeway:32k;

    keyval $host $oidc_authz_endpoint        zone=oidc_authz_endpoint;
    keyval $host $oidc_authz_extra_args      zone=oidc_authz_extra_args;
    keyval $host $oidc_token_endpoint        zone=oidc_token_endpoint;
    keyval $host $oidc_jwt_keyfile           zone=oidc_jwt_keyfile;
    keyval $host $oidc_end_session_endpoint  zone=oidc_end_session_endpoint;
    keyval $host $oidc_client                zone=oidc_client;
    keyval $host $oidc_pkce_enable           zone=oidc_pkce_enable;
    keyval $host $oidc_client_secret         zone=oidc_client_secret;
    keyval $host $oidc_client_auth_method    zone=oidc_client_auth_method;
    keyval $host $oidc_scopes                zone=oidc_scopes;
    keyval $host $oidc_logout_redirect       zone=oidc_logout_redirect;
    keyval $host $oidc_hmac_key              zone=oidc_hmac_key;
    keyval $host $zone_sync_leeway           zone=zone_sync_leeway;

    keyval_zone zone=oidc_id_tokens:32k;
    keyval_zone zone=oidc_access_tokens:32k;
    keyval_zone zone=refresh_tokens:32k;
    keyval_zone zone=oidc_sids:32k;
    keyval_zone zone=oidc_pkce:32k;

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

$Test::Nginx::OIDC::port = $idp_port;
$t->run_daemon(\&idp_daemon, $issuer, $client_id, $jwt_secret)
    ->waitforsocket('127.0.0.1:' . $idp_port);

$t->run();

my $api_version = (sort { $a <=> $b } @{ api('/api/') })[-1];

# Set the init OIDC config values via the API.
set_conf({
    oidc_authz_endpoint        => "http://127.0.0.1:$idp_port/auth",
    oidc_authz_extra_args      => "",
    oidc_token_endpoint        => "http://127.0.0.1:$idp_port/token",
    oidc_jwt_keyfile           => "http://127.0.0.1:$idp_port/certs",
    oidc_end_session_endpoint  => "",
    oidc_client                => $client_id,
    oidc_client_secret         => "test-client-secret",
    oidc_client_auth_method    => "client_secret_post",
    oidc_scopes                => "openid",
    oidc_logout_redirect       => "/_logout",
    oidc_hmac_key              => "test-hmac-key",
    oidc_pkce_enable           => "0",
    zone_sync_leeway           => "0",
}, 1);

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
my $r = http_get('/', $cookie);
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

patch_kv('oidc_id_tokens', { $session_id => undef });
like(http_get('/', $cookie), qr/FOO/, 'session refreshed');

# ###############################################################################

sub http_get {
    my ($url, $cookie) = @_;
    my @headers = (
        "GET $url HTTP/1.0",
        "Host: localhost",
    );

    push @headers, "Cookie: $cookie" if defined $cookie;

    return http(join("\n", @headers) . "\n\n");
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

sub post_kv {
    my ($zone, $data) = @_;
    my $body = JSON::PP::encode_json($data);
    my $len  = length($body);

    return http(<<EOF);
POST /api/$api_version/http/keyvals/$zone HTTP/1.1
Host: localhost
Connection: close
Content-Type: application/json
Content-Length: $len

$body
EOF
}

sub patch_kv {
    my ($zone, $data) = @_;
    my $body = JSON::PP::encode_json($data);
    my $len  = length($body);

    return http(<<EOF);
PATCH /api/$api_version/http/keyvals/$zone HTTP/1.1
Host: localhost
Connection: close
Content-Type: application/json
Content-Length: $len

$body
EOF
}

sub set_conf {
    my ($json, $post, $host) = @_;
    $host //= 'localhost';

    for my $zone (keys %$json) {
        my $value = $json->{$zone};

        my $body = { $host => $value };

        if ($post) {
            post_kv("$zone", $body);
        } else {
            patch_kv("$zone", $body);
        }
    }
}

###############################################################################
