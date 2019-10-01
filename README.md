# nginx-openid-connect

Reference implementation of NGINX Plus as relying party for OpenID Connect authentication

## Description

This repository describes how to enable OpenID Connect integration for [NGINX Plus](https://www.nginx.com/products/nginx/). The solution depends on NGINX Plus components ([auth_jwt module](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html) and [key-value store](http://nginx.org/en/docs/http/ngx_http_keyval_module.html)) and as such is not suitable for [open source NGINX](http://www.nginx.org/en).

<img src=https://www.nginx.com/wp-content/uploads/2018/04/dia-LC-2018-03-30-OpenID-Connect-authorization-code-flow-NGINX-800x426-03.svg alt="OpenID Connect components" width=500>

`Figure 1. High level components of an OpenID Connect environment`

This implementation assumes the following environment:

  * The identity provider (IdP) supports OpenID Connect 1.0
  * The authorization code flow is in use
  * NGINX Plus is configured as a relying party
  * The IdP knows NGINX Plus as a confidential client

With this environment, both the client and NGINX Plus communicate directly with the IdP at different stages during the initial authentication event.

![OpenID Connect protocol diagram](https://www.nginx.com/wp-content/uploads/2018/04/dia-LC-2018-03-30-OpenID-Connect-authentication-code-flow-detailed-800x840-03.svg)
`Figure 2. OpenID Connect authorization code flow protocol`

NGINX Plus is configured to perform OpenID Connect authentication. Upon a first visit to a protected resource, NGINX Plus initiates the OpenID Connect authorization code flow and redirects the client to the OpenID Connect provider (IdP). When the client returns to NGINX Plus with an authorization code, NGINX Plus exchanges that code for a set of tokens by communicating directly with the IdP.

The ID Token received from the IdP is then [validated](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). NGINX Plus then stores the ID token in the key-value store, issues a session cookie to the client using a random string, (which becomes the key to obtain the ID token from the key-value store) and redirects the client to the original URI requested prior to authentication.

Subsequent requests to protected resources are authenticated by exchanging the session cookie for the ID Token in the key-value store. JWT validation is performed on each request, as normal, so that the ID Token validity period is enforced.

For more information on OpenID Connect and JWT validation with NGINX Plus, see [Authenticating Users to Existing Applications with OpenID Connect and NGINX Plus](https://www.nginx.com/blog/authenticating-users-existing-applications-openid-connect-nginx-plus/).

### Refresh Tokens

If a [refresh token](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens) was received from the IdP then it is also stored in the key-value store. When validation of the ID Token fails (typically upon expiry) then NGINX Plus sends the refresh token to the IdP. If the user's session is still valid at the IdP then a new ID token is received, validated, and updated in the key-value store. The refresh process is seamless to the client.

### Logout

Requests made to the `/logout` location invalidate both the ID token and refresh token by erasing them from the key-value store. Therefore, subsequent requests to protected resources will be treated as a first-time request and send the client to the IdP for authentication. Note that the IdP may issue cookies such that an authenticated session still exists at the IdP.

## Installation

The master branch of this repo requires the most recent release of NGINX Plus. Older releases should use the branch corresponding to that NGINX Plus release. For installation instructions, see [Installing NGINX Plus](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-plus/). 

In addition, the [njs module](https://www.nginx.com/blog/introduction-nginscript/) is required for handling the interaction between NGINX Plus and the OpenID Connect provider (IdP). Install the njs module after installing NGINX Plus by running one of the following:

`$ sudo apt install nginx-plus-module-njs` for Debian/Ubuntu

`$ sudo yum install nginx-plus-module-njs` for CentOS/RedHat

The njs module needs to be loaded by adding the following configuration directive near the top of **nginx.conf**.

```nginx
load_module modules/ngx_http_js_module.so;
```

Finally, create a clone of the GitHub repository.

`$ git clone https://github.com/nginxinc/nginx-openid-connect`

> **N.B.** There is a branch for each NGINX Plus release. Switch to the correct branch to ensure compatibility with the features and syntax of each release.

All files can be copied to **/etc/nginx/conf.d**

> **N.B.** The GitHub repository contains [include](http://nginx.org/en/docs/ngx_core_module.html#include) files for NGINX configuration and JavaScript code for token exchange and initial token validation. These files are referenced with a relative path (relative to /etc/nginx). If NGINX Plus is running from a non-standard location then copy the files from the GitHub repository to `/path/to/conf/conf.d` and use the `-p` flag to start NGINX with a prefix path that specifies the location where the configuration files are located.
>
> `nginx -p /path/to/conf -c /path/to/conf/nginx.conf`

## Configuring your IdP

  * Create an OpenID Connect client to represent your NGINX Plus instance
    * Choose the **authorization code flow**
    * Set the **redirect URI** to the address of your NGINX Plus instance (including the port number), with `/_codexch` as the path, e.g. `https://my-nginx.example.com:443/_codexch`
    * Ensure NGINX Plus is configured as a confidential client (with a client secret)
    * Make a note of the `client ID` and `client secret`

  * If your IdP supports OpenID Connect Discovery (usually at the URI `/.well-known/openid-configuration`) then use the `configure.sh` script to complete configuration. In this case you can skip the **frontend.conf** configuration. Otherwise:
    * Obtain the URL for `jwks_uri` or download the JWK file to your NGINX Plus instance
    * Obtain the URL for the **authorization endpoint**
    * Obtain the URL for the **token endpoint**

## Configuring NGINX Plus

Review the following files copied from the GitHub repository so that they match your IdP configuration.

  * **frontend.conf** - this is the reverse proxy configuration and where the IdP is configured. This file can be automatically configured by using the `configure.sh` script.
    * Modify the upstream group to match your backend site or app
    * Modify the `resolver` directive to match a DNS server that is capable of resolving the IdP defined in `$oidc_token_endpoint`
    * Modify the URI defined in `$oidc_logout_redirect` to specify an unprotected resource to be displayed after requesting the `/logout` location
    * Configure the preferred listen port and [enable SSL/TLS configuration](https://docs.nginx.com/nginx/admin-guide/security-controls/terminating-ssl-http/)
    * Set the value of `$oidc_jwt_keyfile` to specify the `jwks_uri` value or match the JWK file downloaded from the IdP (ensuring that it is readable by the NGINX worker processes)
    * Comment/uncomment the `auth_jwt_key_file` or `auth_jwt_key_request` directives based on whether `$oidc_jwt_keyfile` is a file or URI, respectively
    * Modify all of the `set $oidc_` directives to match your IdP configuration
    * Set a unique value for `$oidc_hmac_key` to ensure nonce values are unpredictable

  * **openid_connect.server_conf** - this is the NGINX configuration for handling the various stages of OpenID Connect authorization code flow
    * No changes are usually required here
    * If using [`auth_jwt_key_request`](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html#auth_jwt_key_request) to automatically fetch the JWK file from the IdP then modify the validity period and other caching options to suit your IdP
    * Modify the `add_header Set-Cookie` directives with appropriate [cookie flags](https://en.wikipedia.org/wiki/HTTP_cookie#Terminology) to control the scope of single sign-on and security options, e.g. Domain; Path; Secure;

  * **openid_connect.js** - this is the JavaScript code for performing the authorization code exchange and nonce hashing
    * No changes are required unless modifying the code exchange or validation process

### Configuring the Key-Value Store

The key-value store is used to maintain persistent storage for ID tokens and refresh tokens. The default configuration should be reviewed so that it suits the environment.

```nginx
keyval_zone zone=opaque_sessions:1M state=conf.d/opaque_sessions.json timeout=1h;
keyval_zone zone=refresh_tokens:1M  state=conf.d/refresh_tokens.json  timeout=8h;
```

Each of the `keyval_zone` parameters are described below.

  * **zone** - Specifies the name of the key-value store and how much memory to allocate for it. Each session will typically occupy 1-2KB, depending on the size of the JWT, so scale this value to exceed the number of unique users that may authenticate.

  * **state** (optional) - Specifies where all of the ID Tokens in the key-value store are saved, so that sessions will persist across restart or reboot of the NGINX host. The NGINX Plus user account, typically **nginx**, must have write permission to the directory where the state file is stored. Consider creating a dedicated directory for this purpose.

  * **timeout** - Expired tokens are removed from the key-value store after the `timeout` value. This should be set to value slightly longer than the JWT validity period. JWT validation occurs on each request, and will fail when the expiry date (`exp` claim) has elapsed. If JWTs are issued without an `exp` claim then set `timeout` to the desired session duration. If JWTs are issued with a range of validity periods then set `timeout` to exceed the longest period.

  * **sync** (optional) - If deployed in a cluster, the key-value store may be synchronized across all instances in the cluster, so that all instances are able to create and validate authenticated sessions. Each instance must be configured to participate in state sharing with the [zone_sync module](http://nginx.org/en/docs/stream/ngx_stream_zone_sync_module.html) and by adding the `sync` parameter to the `keyval_zone` directives above.

## Session Management

The [NGINX Plus API](http://nginx.org/en/docs/http/ngx_http_api_module.html) is enabled in **openid_connect.server_conf** so that sessions can be monitored. The API can also be used to manage the current set of active sessions.

To query the current sessions in the key-value store:

```shell
$ curl localhost:8010/api/4/http/keyvals/opaque_sessions
```

To delete a single session:

```shell
$ curl -iX PATCH -d '{"<session ID>":null}' localhost:8010/api/4/http/keyvals/opaque_sessions
$ curl -iX PATCH -d '{"<session ID>":null}' localhost:8010/api/4/http/keyvals/refresh_tokens
```

To delete all sessions:

```shell
$ curl -iX DELETE localhost:8010/api/3/http/keyvals/opaque_sessions
$ curl -iX DELETE localhost:8010/api/3/http/keyvals/refresh_tokens
```

## Troubleshooting

Any errors generated by the OpenID Connect flow are logged in a separate file, `/var/log/nginx/oidc_error.log`. Check the contents of this file as it may include error responses received by the IdP.

  * **400 error from IdP**
    * This is typically caused by incorrect configuration related to the client ID and client secret.
    * Check the values of the `$oidc_client` and `$oidc_client_secret` variables against the IdP configuration.

  * **Authentication is successful but browser shows too many redirects**
    * This is typically because the JWT sent to the browser cannot be validated, resulting in 'authorization required' `401` response and starting the authentication process again. But the user is already authenticated so is redirected back to NGINX,  hence the redirect loop.
    * Check the error log `/var/log/nginx/oidc_error.log` for JWT/JWK errors.
    * Ensure that the JWK file (`$oidc_jwt_keyfile` variable) is correct and that the nginx user has permission to read it.

  * **Logged out but next request does not require authentication**
    * This is typically caused by the IdP issuing its own session cookie(s) to the client. NGINX Plus sends the request to the IdP for authentication and the IdP immediately sends back a new authorization code because the session is still valid.
    * Check your IdP configuration if this behavior is not desired.

## Support

This reference implementation for OpenID Connect is supported for NGINX Plus subscribers.

## Changelog

  * **R15** Initial release of OpenID Connect reference implementation
  * **R16** Added support for opaque session tokens using key-value store
  * **R17** Configuration now supports JSON Web Key (JWK) set to be obtained by URI
  * **R18** Opaque session tokens now used by default. Added support for refresh tokens. Added `/logout` location.
  * **R19** Minor bug fixes

