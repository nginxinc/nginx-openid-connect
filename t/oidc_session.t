#!/usr/bin/perl

# (C) Ivan Ovchinnikov
# (C) Nginx, Inc.

# Tests for njs-based OIDC SSO solution.

###################################################################################################

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

###################################################################################################

select STDERR; $| = 1;
select STDOUT; $| = 1;

eval { require JSON::PP; };
plan(skip_all => "JSON::PP not installed") if $@;

my $idp_port   = port(8082);
my $client_id  = 'test-client';
my $jwt_secret = 'test-jwt-secret';
my $issuer     = "http://127.0.0.1:$idp_port";

my $t = Test::Nginx->new()->has(qw/http/)->plan(125);
my $d = $t->testdir();

###################################################################################################
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
    keyval_zone zone=oidc_debug:32k;
    keyval_zone zone=oidc_log_format:32k;

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
    keyval $host $oidc_debug                 zone=oidc_debug;
    keyval $host $oidc_log_format            zone=oidc_log_format;

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
    oidc_debug                 => "1",
    oidc_log_format            => "",
}, 1);

###################################################################################################

### initial_auth_success

my $start_uri = '/?foo=bar&baz=qux';
my $flow = parse_response(get($start_uri));

like($flow->{location}, qr/^\Q$issuer\E\/auth\?/, 'auth redirects to IdP');

is($flow->{response_type}, 'code', 'auth req response_type=code');
is($flow->{scope}, 'openid', 'auth req scope=openid');

ok(defined $flow->{state} && defined $flow->{nonce}, 'auth req state and nonce');
is($flow->{client_id}, $client_id, 'auth req client_id');

like($flow->{redirect_uri}, qr!^https?://localhost:8080/_codexch$!, 'auth req redirect_uri');

my $set_cookie = join "\n", @{ $flow->{headers}{'set-cookie'} };
like($set_cookie, qr/\bauth_redir=%2F%3Ffoo%3Dbar%26baz%3Dqux;/, 'auth_redir cookie');
like($set_cookie, qr/\bauth_nonce=[0-9a-f]{32};/i, 'auth_nonce cookie');

set_state(nonce => $flow->{nonce});

$flow = http(build_code_request($flow));
$flow = parse_response($flow);

like($flow->{cookie}, qr/^auth_token=[^;]+;/, 'auth_token cookie');
like($flow->{location}, qr!^http://localhost(?::\d+)?/\?foo=bar&baz=qux$!,
    'callback redirects to orig uri');

my $cookie = $flow->{cookie};
my $r = get('/', $cookie);
my $s = get_state();

like($r, qr/FOO/, 'successful auth');
like($r, qr/X-Test-AT: \Q$s->{access_token}\E/s, 'access token var');
like($r, qr/X-Test-ID: \Q$s->{id_token}\E/s, 'id token var');
like($r, qr/X-Test-ISS: \Q$issuer\E/s, 'iss claim var');
is($s->{token_hits}, 1, 'one tokenset request');

my $sid = $flow->{session_id};

is(get_kv('oidc_id_tokens')->{$sid}, $s->{id_token}, 'kv stores id_token');
is(get_kv('oidc_access_tokens')->{$sid}, $s->{access_token}, 'kv stores access_token');
is(get_kv('refresh_tokens')->{$sid}, $s->{refresh_token},'kv stores refresh_token');
is(get_kv('oidc_sids')->{sid1}, $sid, 'kv maps sid to session id');
is_deeply(get_kv('oidc_pkce'), {}, 'kv pkce is empty when pkce is disabled');

### authz_extra_args

set_conf({ oidc_authz_extra_args => "foo=bar&baz=qux" });
$flow = parse_response(get('/'));

like($flow->{location}, qr/foo=bar&baz=qux/, 'authz_extra_args in auth redir');

### refresh_success

($cookie, $sid) = fresh_session('/');
my $hits_before = get_state()->{token_hits};
my $id_before = get_kv('oidc_id_tokens')->{$sid};
my $access_before = get_kv('oidc_access_tokens')->{$sid};
my $refresh_before = get_kv('refresh_tokens')->{$sid};
patch_kv('oidc_id_tokens', { $sid => undef });

$r = get('/', $cookie);
like($r, qr/FOO/, 'session refreshed');

my $hits_after = get_state()->{token_hits};
is($hits_after, $hits_before + 1, 'refresh tokenset request');
my $id_after = get_kv('oidc_id_tokens')->{$sid};
isnt($id_after, $id_before, 'id token rotated');
my $access_after = get_kv('oidc_access_tokens')->{$sid};
isnt($access_after, $access_before, 'access token rotated');
my $refresh_after = get_kv('refresh_tokens')->{$sid};
isnt($refresh_after, $refresh_before, 'refresh token rotated');

### refresh_error_400_json (TODO: check redir to orig uri)

($cookie, $sid) = fresh_session('/');
patch_kv('oidc_id_tokens', { $sid => undef });
patch_kv('refresh_tokens', { $sid => 'foo' });
$flow = parse_response(get('/?foo=bar', $cookie));

is($flow->{status}, 302, 'refresh 400 json error returns 302');
like($flow->{raw}, qr/\r?\nLocation:\s*\r?\n/s, 'refresh 400 json redirect');
like(get_logs(), qr/refresh\s+failure.*invalid_grant.*invalid refresh_token/s,
    'refresh 400 json error log');

### refresh_error_none_400 (TODO: check redir to orig uri)

($cookie, $sid) = fresh_session('/');
patch_kv('oidc_id_tokens', { $sid => undef });
set_state(token_status => 500);
$flow = parse_response(get('/?foo=baz', $cookie));
set_state(token_status => '');

is($flow->{status}, 302, 'refresh 500 error returns 302');
like(get_logs(), qr/refresh\s+failure.*500/s, 'refresh status 500 error log');

### refresh_200_json_without_id_token

($cookie, $sid) = fresh_session('/');
patch_kv('oidc_id_tokens', { $sid => undef });
set_state(token_status => 201);
$flow = parse_response(get('/?foo=qux', $cookie));
set_state(token_status => '');

like(get_logs(), qr/refresh\s+response\s+did\s+not\s+include\s+id_token/s,
    'refresh without id_token error log');

### refresh_success_but_validate_fails

($cookie, $sid) = fresh_session('/');
patch_kv('oidc_id_tokens', { $sid => undef });
set_state(client_id => 'foo');
$flow = parse_response(get('/?foo=aud', $cookie));
set_state(client_id => $client_id);

is($flow->{status}, 302, 'refresh with invalid id_token claims returns 302');
like($flow->{raw}, qr/\r?\nLocation:\s*\r?\n/s, 'refresh validate failure redirect');
like(get_logs(), qr/aud\s+claim.*does\s+not\s+include/s, 'refresh validate error log');
is(get_kv('refresh_tokens')->{$sid}, '-', 'refresh token kv reset');

### pkce_enable

set_conf({ oidc_pkce_enable => "1" });
$flow = parse_response(get('/'));

is($flow->{code_challenge_method}, 'S256', 'pkce code_challenge_method');
like($flow->{code_challenge}, qr/^[A-Za-z0-9_-]{43}$/, 'pkce code_challenge base64url');
like($flow->{state}, qr/^[A-Za-z0-9_-]{43}$/, 'pkce state base64url');
ok(exists get_kv('oidc_pkce')->{$flow->{state}}, 'kv pkce entry exists');

$flow = run_oidc_flow('/');
like($flow->{cookie}, qr/^auth_token=[^;]+;/, 'pkce auth success');

$s = get_state();
like($s->{code_verifier}, qr/^[0-9a-f]{64}$/i, 'pkce code_verifier sent to token request');
is($s->{auth_method}, '', 'pkce token request no client auth');

set_conf({ oidc_pkce_enable => "0" });

### code_exchange_error

$flow = parse_response(get('/_codexch?error=access_denied&error_description=nope'));

is($flow->{status}, 502, 'code exchange 502 error');
like($flow->{raw}, qr/authorization\s+code.*nope/s, 'code exchange error log');

### id_token_missing_claim

set_state(client_id => "");
$flow = run_oidc_flow('/');

is($flow->{status}, 500, 'id_token missing required claim returns 500');
like($flow->{raw}, qr/missing\s+claim\(s\).*aud/s, 'id_token missing aud claim log');

set_state(client_id => $client_id);

### id_token_aud_mismatch

set_state(client_id => "foo");
$flow = run_oidc_flow('/');

is($flow->{status}, 500, 'id_token aud mismatch returns 500');
like($flow->{raw}, qr/aud\s+claim.*foo.*does\s+not\s+include.*test-client/s,
    'id_token aud mismatch log');

set_state(client_id => $client_id);

### id_token_nonce_mismatch

$flow = parse_response(get('/'));
set_state(nonce => 'wrong');
$flow = parse_response(http(build_code_request($flow)));

is($flow->{status}, 500, 'id_token nonce mismatch returns 500');
like($flow->{raw}, qr/nonce.*wrong.*does\s+not\s+match\s+client/s,
    'id_token nonce mismatch log');

### id_token_nonce_missing_initial_auth

$flow = parse_response(get('/'));
set_state(nonce => '');
$flow = parse_response(http(build_code_request($flow)));

is($flow->{status}, 500, 'id_token missing nonce returns 500');
like($flow->{raw}, qr/missing\s+nonce\s+claim.*initial\s+authentication/s,
    'id_token missing nonce in initial auth log');

### id_token_nonce_missing_cookie_nonce

$flow = parse_response(get('/'));
set_state(nonce => $flow->{nonce});
$flow = parse_response(http(build_code_request($flow, cookie => '')));

is($flow->{status}, 500, 'id_token nonce without cookie nonce returns 500');
like($flow->{raw}, qr/nonce.*does\s+not\s+match\s+client\s+\(\)/s,
    'id_token nonce mismatch with empty client hash log');

### token_error_504

set_state(token_status => 504);
$flow = run_oidc_flow('/');

is($flow->{status}, 504, 'token 504 path returns 504');
like($flow->{raw}, qr/timeout.*code\s+exchange/s, 'token 504 log');

set_state(token_status => '');

### token_error_non_json

set_state(token_status => 400);
$flow = run_oidc_flow('/');

is($flow->{status}, 502, 'token non-200 non-json returns 502');
like($flow->{raw}, qr/unexpected\s+response.*HTTP 400/s, 'token non-json response log');

set_state(token_status => '');

### token_error_json_without_error

set_state(token_status => 401);
$flow = run_oidc_flow('/');

is($flow->{status}, 502, 'token non-200 json without error returns 502');
like($flow->{raw}, qr/unexpected\s+response.*HTTP 400/s, 'token json without error log');

set_state(token_status => '');

### token_error_json_200

set_state(token_status => 201);
$flow = run_oidc_flow('/');

is($flow->{status}, 500, 'token 200 with tokenset.error returns 500');
like($flow->{raw}, qr/token\s+response\s+error.*invalid_client.*nope/s,
    'token 200 with error log');

set_state(token_status => '');

### token_success_non_json

set_state(token_status => 202);
$flow = run_oidc_flow('/');

is($flow->{status}, 502, 'token 200 non-json returns 502');
like($flow->{raw}, qr/token\s+response\s+not\s+JSON.*not json/s,
    'token 200 non-json log');

set_state(token_status => '');

### token_error_json

$flow = run_oidc_flow('/', code => 'bad-code');

is($flow->{status}, 502, 'token non-200 json error returns 502');
like($flow->{raw}, qr/error\s+from\s+IdP.*invalid_grant.*unknown code/s,
    'token json error log');

### client_secret_post_basic

$flow = run_oidc_flow('/');
$s = get_state();

is($s->{auth_method}, 'post', 'client_secret_post auth');
is($s->{auth_secret}, 'test-client-secret', 'client_secret_post secret');

set_conf({ oidc_client_auth_method => 'client_secret_basic' });
$flow = run_oidc_flow('/');
$s = get_state();

is($s->{auth_method}, 'basic', 'client_secret_basic auth');
is($s->{auth_secret}, 'test-client-secret', 'client_secret_basic secret');

### missing_config

set_conf({ oidc_hmac_key => "" });
$flow = parse_response(get('/'));

is($flow->{status}, 500, 'missing required config returns 500');
like(get_logs(), qr/missing.*\$oidc_hmac_key/is, 'missing config error log');

set_conf({ oidc_hmac_key => "test-hmac-key" });

### logout_without_end_session_relative_redirect

($cookie, $sid) = fresh_session('/');
$flow = parse_response(get('/logout', $cookie));

is($flow->{status}, 302, 'logout without end_session returns 302');
like($flow->{location}, qr!^http://localhost(?::\d+)?/_logout$!, 'logout relative redirect');

is(get_kv('oidc_id_tokens')->{$sid}, '-', 'logout clears id_token');
is(get_kv('oidc_access_tokens')->{$sid}, '-', 'logout clears access_token');
is(get_kv('refresh_tokens')->{$sid}, '-', 'logout clears refresh_token');
is(get_kv('oidc_sids')->{sid1}, '-', 'logout clears sid');

$set_cookie = join "\n", @{ $flow->{headers}{'set-cookie'} || [] };
like($set_cookie, qr/\bauth_token=;\s*Path=\/;\s*SameSite=lax;/, 'logout clears auth_token cookie');
like($set_cookie, qr/\bauth_nonce=;\s*Path=\/;\s*SameSite=lax;/, 'logout clears auth_nonce cookie');
like($set_cookie, qr/\bauth_redir=;\s*Path=\/;\s*SameSite=lax;/, 'logout clears auth_redir cookie');

### logout_without_end_session_absolute_redirect

set_conf({ oidc_logout_redirect => "https://example.com/foo" });
($cookie, $sid) = fresh_session('/');
$flow = parse_response(get('/logout', $cookie));

is($flow->{status}, 302, 'logout absolute redirect returns 302');
is($flow->{location}, 'https://example.com/foo', 'logout absolute redirect');

### logout_claims_error_still_redirects

set_conf({ oidc_logout_redirect => "/_logout" });
($cookie, $sid) = fresh_session('/');
patch_kv('oidc_id_tokens', { $sid => 'not-a-jwt' });
$flow = parse_response(get('/logout', $cookie));

is($flow->{status}, 302, 'logout broken id_token returns 302');
like($flow->{location}, qr!^http://localhost(?::\d+)?/_logout$!,
    'logout broken id_token redirects to logout target');
is(get_kv('oidc_id_tokens')->{$sid}, '-', 'logout broken id_token clears id_token');
is(get_kv('oidc_access_tokens')->{$sid}, '-', 'logout broken id_token clears access_token');
is(get_kv('refresh_tokens')->{$sid}, '-', 'logout broken id_token clears refresh_token');
is(get_kv('oidc_sids')->{sid1}, $sid, 'logout broken id_token keeps sid mapping');

### logout_with_end_session_and_id_token_hint

set_conf({ oidc_end_session_endpoint => "http://127.0.0.1:$idp_port/end_session" });
($cookie, $sid) = fresh_session('/');
my $session_jwt = get_kv('oidc_id_tokens')->{$sid};
$flow = parse_response(get('/logout', $cookie));

is($flow->{status}, 302, 'rp-logout returns 302');
like($flow->{location}, qr!^\Qhttp://127.0.0.1:$idp_port/end_session\E\?!,
    'rp-logout redirects to end_session endpoint');
like($flow->{location},
    qr/[?&]post_logout_redirect_uri=http%3A%2F%2Flocalhost(?:%3A\d+)?%2F_logout(?:&|$)/,
    'rp-logout encoded post_logout_redirect_uri');
is($flow->{id_token_hint}, $session_jwt, 'rp-logout id_token_hint');

### logout_with_end_session_refresh_when_id_token_missing

($cookie, $sid) = fresh_session('/');
$hits_before = get_state()->{token_hits};
patch_kv('oidc_id_tokens', { $sid => undef });
$flow = parse_response(get('/logout', $cookie));
$s = get_state();

like($flow->{location}, qr!^\Qhttp://127.0.0.1:$idp_port/end_session\E\?!,
    'rp-logout with token refresh');
is($s->{token_hits}, $hits_before + 1, 'rp-logout triggers tokenset req');
is($flow->{id_token_hint}, $s->{id_token}, 'rp-logout refreshed id_token_hint');

### logout_with_end_session_no_id_token_no_refresh_token

($cookie, $sid) = fresh_session('/');
$hits_before = get_state()->{token_hits};
patch_kv('oidc_id_tokens', { $sid => undef });
patch_kv('refresh_tokens', { $sid => undef });
$flow = parse_response(get('/logout', $cookie));
$s = get_state();

is($flow->{status}, 302, 'rp-logout no id_token no refresh_token returns 302');
like($flow->{location}, qr!^http://localhost(?::\d+)?/_logout$!,
    'rp-logout no id_token no refresh_token redirects to local logout');

### frontchannel_logout_missing_sid

$flow = parse_response(get('/front_channel_logout?iss=test-issuer'));

is($flow->{status}, 400, 'fc-logout w/o sid returns 400');
like(get_logs(), qr/missing sid parameter in front-channel logout request/i,
    'fc-logout w/o sid error log');

### frontchannel_logout_missing_iss

$flow = parse_response(get('/front_channel_logout?sid=sid1'));

is($flow->{status}, 400, 'fc-logout w/0 iss returns 400');
like(get_logs(), qr/missing iss parameter in front-channel logout request/i,
    'fc-logout w/o iss error log');

### frontchannel_logout_sid_not_found

$flow = parse_response(get('/front_channel_logout?sid=foo&iss=' . $issuer));

like($flow->{raw}, qr/Logout successful/s, 'fc-logout unknown sid success logout');

### frontchannel_logout_issuer_mismatch

($cookie, $sid) = fresh_session('/');
$flow = parse_response(get('/front_channel_logout?sid=sid1&iss=foo'));

is($flow->{status}, 400, 'fc-logout w/ issuer mismatch returns 400');
like(get_logs(), qr/frontchannel\.issMismatch/, 'fc-logout w/ issuer mismatch error log');

### frontchannel_logout_success_cleans_session

($cookie, $sid) = fresh_session('/');
$flow = parse_response(get('/front_channel_logout?sid=sid1&iss=' . $issuer));

is($flow->{status}, 200, 'fc-logout success returns 200');
is(get_kv('oidc_id_tokens')->{$sid}, '-', 'fc-logout clears id_token');
is(get_kv('oidc_access_tokens')->{$sid}, '-', 'fc-logout clears access_token');
is(get_kv('refresh_tokens')->{$sid}, '-', 'fc-logout success clears refresh_token');
is(get_kv('oidc_sids')->{sid1}, '-', 'fc-logout clears sid mapping');

### frontchannel_logout_token_refresh

($cookie, $sid) = fresh_session('/');
patch_kv('oidc_id_tokens', { $sid => undef });
$flow = parse_response(get('/front_channel_logout?sid=sid1&iss=' . $issuer));

is($flow->{status}, 200, 'fc-logout w/ token refresh returns 200');
is(get_kv('oidc_id_tokens')->{$sid}, '-', 'fc-logout w/ token refresh clears id_token');
is(get_kv('oidc_access_tokens')->{$sid}, '-', 'fc-logout w/ token refresh clears access_token');
is(get_kv('refresh_tokens')->{$sid}, '-', 'fc-logout w/ token refresh clears refresh_token');
is(get_kv('oidc_sids')->{sid1}, '-', 'fc-logout w/ token refresh clears sid mapping');

### oidc_error_json_log_format

set_conf({ oidc_log_format => "json" });
$flow = parse_response(get('/_codexch'));

my $logs = get_logs();
my @json_log_lines = ($logs =~ /js:\s+(\{[^\n]*\})/g);
my $json_error = {};
my $decoded_ok = eval {
    $json_error = JSON::PP::decode_json($json_log_lines[-1]);
    1;
};

ok($decoded_ok, 'oidc_error json line is parseable via JSON::PP');
for my $key (qw/refId message clientIp host method uri httpVersion/) {
    ok(exists $json_error->{$key}, "oidc_error json has key $key");
}
like($json_error->{message} // '', qr/OIDC expected authorization code but received: \/_codexch/,
    'oidc_error json has expected message');

###################################################################################################

sub get {
    my ($url, $cookie) = @_;
    my @headers = (
        "GET $url HTTP/1.0",
        "Host: localhost",
    );

    push @headers, "Cookie: $cookie" if defined $cookie;

    return http(join("\n", @headers) . "\n\n");
}

sub run_oidc_flow {
    my ($path, %code_args) = @_;
    $path //= '/';

    my $flow = parse_response(get($path));
    set_state(nonce => $flow->{nonce}) if defined $flow->{nonce};
    return parse_response(http(build_code_request($flow, %code_args)));
}

sub fresh_session {
    my ($path, %code_args) = @_;
    $path //= '/';

    my $flow = run_oidc_flow($path, %code_args);
    return ($flow->{cookie}, $flow->{session_id});
}

sub api {
    get(shift) =~ /\x0d\x0a?\x0d\x0a?(.*)/ms;
    return eval $1;
}

sub get_kv {
    my ($zone) = @_;
    my $r = get("/api/$api_version/http/keyvals/$zone");
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

sub get_logs {
    my $path  = "$d/error.log";
    my $pos   = 0;
    my @lines = ();

    open my $fh, '<', $path
        or die "Can't open $path: $!\n";

    my $size = -s $path;
    if ($pos > $size) {
        $pos = 0;
        @lines = ();
    }

    seek($fh, $pos, 0)
        or die "Can't seek $path: $!\n";

    while (my $line = <$fh>) {
        push @lines, $line;
        shift @lines while @lines > 100;
    }

    $pos = tell($fh);
    close $fh;

    return join '', @lines;
}

###################################################################################################
