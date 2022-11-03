# nginx-openid-connect

Reference implementation of NGINX Plus as relying party for OpenID Connect authentication

<!-- START doctoc generated TOC please keep comment here to allow auto update -->
<!-- DON'T EDIT THIS SECTION, INSTEAD RE-RUN doctoc TO UPDATE -->

- [Overview](#overview)
  - [Requirements](#requirements)
  - [Authorization Code Grant Flow](#authorization-code-grant-flow)
  - [OpenID Connect UserInfo Endpoint](#openid-connect-userinfo-endpoint)
  - [Logout Behavior](#logout-behavior)
  - [Multiple IdPs](#multiple-idps)
- [Documentation](#documentation)
- [Support](#support)

<!-- END doctoc generated TOC please keep comment here to allow auto update -->

## Overview

This repository provides a reference implementation for setting up [NGINX Plus](https://www.nginx.com/products/nginx/) integrations with OpenID Connect (OIDC). By implementing this solution, you can allow users to access your application by logging in with a supported Identity Provider (IdP).

> **Note**: This solution requires modules that are only available in NGINX Plus: [auth_jwt module](https://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html) and [key-value store](https://nginx.org/en/docs/http/ngx_http_keyval_module.html). It cannot be used with [NGINX open source](http://www.nginx.org/en).

The OpenID Connect solution's basic authorization flow is shown in Figure 1. In this flow, NGINX Plus acts as a relying party that uses the IdP's authorization to allow access to your backend application.

![OpenID Connect Authorization Flow](https://www.nginx.com/wp-content/uploads/2018/04/dia-LC-2018-03-30-OpenID-Connect-authorization-code-flow-NGINX-800x426-03.svg "Figure 1: High-level authorization flow with OpenID Connect and NGINX Plus")

### Requirements

This solution requires the following:

- NGINX Plus and the `njs` module
- An Identity Provider (IdP) that supports [OpenID Connect 1.0](https://openid.net/connect/).
- Your application and IdP support the OIDC authorization code grant flow shown in Figure 2.
- The IdP can recognize NGINX Plus as a confidential client or a public client using PKCE.

## Documentation

This document provides an overview of the OIDC solution and things to take into consideration when designing your own solution. Consult the documentation for setup and testing instructions:

- [Quick Start Guide](https://github.com/nginx-openid-connect/nginx-oidc-examples/blob/main/001-oidc-local-test/README.md) - set up a local demo that can be used for testing purposes
- [Getting Started Guide](/docs/02-getting-started.md) - installation, configuration, and troubleshooting instructions for the OIDC reference implementation

## Authorization Code Grant Flow

The [OAuth 2.0 Authorization Code Grant](https://oauth.net/2/grant-types/authorization-code/) consists of the exchange of an authorization code for an access token between confidential and public clients. In this solution, NGINX Plus acts as a relying party to handle the exchange and ultimately allow or deny access to the requested web application.

![OpenID Connect protocol diagram](https://www.nginx.com/wp-content/uploads/2018/04/dia-LC-2018-03-30-OpenID-Connect-authentication-code-flow-detailed-800x840-03.svg "Figure 2. OpenID Connect authorization code flow protocol")

> **Note:** The [openid_connect.server_conf](openid_connect.server_conf) configuration file sets up this authorization flow.

When a client requests access to a protected resource for the first time, NGINX Plus initiates the authorization code flow and redirects you to the configured OIDC IdP to log in. After you successfully log in, the IdP sends a redirect URL to the browser, along with an authorization code. The browser then redirects your request and the authorization code to the URL for your NGINX Plus instance, at the `/_codexch` location (for example: `http://myapp.example.com/_codexch).

NGINX Plus then communicates with the IdP to exchange the authorization code for a set of authentication tokens.

> **Note:** This generally includes an ID token and an access token, and may include a refresh token as well. The ID token is used for user authentication, while the access token authorizes access to IdP endpoints -- such as `/userinfo` -- or to custom backend APIs. We'll get to the refresh token soon.

Next, NGINX Plus [validates the tokens](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation) that it received from the IdP. It adds the tokens to the key-value store, then issues a session cookie to the client. The session cookie is used to access the key-value store on later visits, allowing authentication to persist across the lifetime of the session. Finally, the request is sent to the URL that was originally requested -- with the session cookie included in the header -- and the client is allowed to access the requested page.

When you request access to other pages in the same protected location, NGINX Plus uses the session cookie to retrieve the ID token from the key-value store. NGINX Plus performs JSON Web Token (JWT) validation on each request to enforce the ID token's validity period.

As noted earlier, an IdP may also provide a [refresh token](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokens). In these cases, NGINX Plus also adds the refresh token to the key-value store. When ID token validation fails -- which typically happens when the token expires -- NGINX Plus uses the refresh token to generate a new set of ID and access tokens. If the session with the IdP is still valid, the IdP sends a new ID token and access token to NGINX Plus. NGINX Plus then validates the tokens as usual and updates the key-value store. This refresh process is seamless to the client.

## OpenID Connect UserInfo Endpoint

The [OpenID Connect UserInfo endpoint](https://openid.net/specs/openid-connect-core-1_0.html#UserInfo) (`/userinfo`) provides details about the logged-in user. Requests to `/userinfo` must be authenticated using the access token provided as part of the authorization code flow.

- When a user is not logged in, requests to the `/userinfo` endpoint return a `401` (unauthorized) response.
- When a user is logged in, requests to `/userinfo` return a `200` response with the requested user information (such as name).

The `/userinfo` endpoint location is stored in the NGINX Plus OIDC configuration as the `$oidc_userinfo_endpoint` variable. In the example configuration below, the `location` context provides a front-end application access to the IdP's `/userinfo` endpoint. The `access_token` value comes from the NGINX Plus exchange with the IdP, while the `oidc_jwt_keyfile` and `oidc_userinfo_endpoint` values come from the IdP configuration.

```
#
# User information endpoint used for the following purposes:
# - Browser to periodically check if you are signed in, based on status code.
# - Browser to show the signed-in user information.
# - https://openid.net/specs/openid-connect-core-1_0.html#UserInfo
#
location = /userinfo {
    auth_jwt "" token=$access_token;      # Access token for API authorization
    #auth_jwt_key_file $oidc_jwt_keyfile; # Enable when using filename
    auth_jwt_key_request /_jwks_uri;      # Enable when using URL

    proxy_ssl_server_name on;             # For SNI to the IdP
    proxy_set_header Authorization "Bearer $access_token";
    proxy_pass       $oidc_userinfo_endpoint;
    access_log /var/log/nginx/access.log oidc_jwt;
}
```

## Logout Behavior

When a client requests an application's `/logout` location, NGINX Plus invalidates the ID, access, and refresh tokens by erasing them from the key-value store. Any additional client requests to protected resources will be redirected to the IdP for authentication.

> **Note:** When NGINX Plus -- which is a "Relying Party" (RP) -- performs a logout, an authenticated session may still exist with the IdP. OIDC provides a spec for [RP-Initiated Logout](https://openid.net/specs/openid-connect-rpinitiated-1_0.html#RPLogout) to ensure the logout is also performed with the IdP.

To avoid breaking changes of API endpoints to customers, the OIDC RP-Initiated Logout spec adds the `/v2/logout` location. This location is used to interact with the IdP's `end_session_endpoint`, which handles RP-Initiated logout requests. The `$post_logout_return_uri` is the URI to which the RP is requesting that the End-User's User Agent be redirected after a logout has been performed.

The examples in this repository use the `/v1/_logout` for IdP configurations. You can change this to use `/v2/logout` according to your needs.

> Note: Support for the `/v2/logout` endpoint was introduced in NGINX Plus R29.

## Using NGINX Plus with Multiple IdPs

NGINX Plus can be configured to proxy requests for multiple websites or applications, or user groups, which may require authentication by different IdPs. You can configure NGINX Plus to use multiple IdPs, with each one matching on an attribute of the HTTP request (for example, hostname or part of the URI path).

> **Note:** When validating OpenID Connect tokens, NGINX Plus can be configured to read the signing key (JWKS) from disk or via a URL. When using multiple IdPs, **each must be configured to use the same method**. Using a mix of both disk and URLs for the `map...$oidc_jwt_keyfile` variable is not supported.

## Support

This reference implementation for OpenID Connect is supported for NGINX Plus subscribers.
