# nginx-openid-connect

Reference implementation of NGINX Plus as relying party for OpenID Connect authentication

## Description

This repository describes how to enable OpenID Connect integration for [NGINX Plus](https://www.nginx.com/products/nginx/). The solution depends on the [auth_jwt](http://nginx.org/en/docs/http/ngx_http_auth_jwt_module.html) module and as such is not suitable for [open source NGINX](http://www.nginx.org/en).

<img src=https://www.nginx.com/wp-content/uploads/2018/04/dia-LC-2018-03-30-OpenID-Connect-authorization-code-flow-NGINX-800x426-03.svg alt="OpenID Connect components" width=500>

`Figure 1. High level components of an OpenID Connect environment`

This implementation assumes the following environment:

  * The identity provider (IdP) supports OpenID Connect 1.0
  * The authorization code flow is in use
  * NGINX Plus is configured as a relying party
  * The IdP knows NGINX Plus as a condifential client

With this environment, both the client and NGINX Plus communicate directly with the IdP at different stages during the initial authentication event.

![OpenID Connect protocol diagram](https://www.nginx.com/wp-content/uploads/2018/04/dia-LC-2018-03-30-OpenID-Connect-authentication-code-flow-detailed-800x840-03.svg)
`Figure 2. OpenID Connect authorization code flow protocol`

NGINX Plus is configured to perform OpenID Connect authentication. Upon a first visit to a protected resource, NGINX Plus initiates the OpenID Connect authorization code flow and redirects the client to the OpenID Connect provider (IdP). When the client returns to NGINX Plus with an authorization code, NGINX Plus exchanges that code for a set of tokens by communicating directly with the IdP.

The ID Token received from the IdP is then [validated](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). NGINX Plus then issues a session cookie to the client using either the ID Token or the Access Token and is redirected to the original URI requested prior to authentication.

Subsequent requests to protected resources are authenticated using the session cookie by performing JWT validation.
 
For more information on OIDC and NGINX Plus JWT support, see [Authenticating Users to Existing Applications with OpenID Connect and NGINX Plus](https://www.nginx.com/blog/authenticating-users-existing-applications-openid-connect-nginx-plus/).

## Installation

OpenID Connect integration requires NGINX Plus R15 or later to be installed. See [Installing NGINX Plus](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-plus/).

In addition, the [njs module](https://www.nginx.com/blog/introduction-nginscript/) is required for handling the interaction between NGINX Plus and the OpenID Connect provider (IdP). Install the njs module after installing NGINX Plus by running one of the following:

`$ sudo apt install nginx-plus-module-njs` for Debian/Ubuntu

`$ sudo yum install nginx-plus-module-njs` for CentOS/RedHat

The njs module needs to be loaded by adding the following configuration directive near the top of **nginx.conf**.

```nginx
load_module modules/ngx_http_js_module.so;
```

Finally, create a clone of the GitHub repository.

`$ git clone https://github.com/nginxinc/nginx-openid-connect`

All files can be copied to **/etc/nginx/conf.d**

> **N.B.** The GitHub repository contains [include](http://nginx.org/en/docs/ngx_core_module.html#include) files for NGINX configuration and JavaScript code for token exchange and initial token validation. These files are referenced with a relative path (relative to /etc/nginx). If NGINX Plus is running from a non-standard location then copy the files from the GitHub repository to `/path/to/conf/conf.d` and use the `-p` flag to start NGINX with a prefix path that specifies the location where the configuration files are located.
>
> `nginx -p /path/to/conf -c /path/to/conf/nginx.conf`

## Configuring your IdP

  * Create an OpenID Connect client to represent your NGINX Plus instance
    * Choose the **authorization code flow**
    * Set the **redirect URI** to the address of your NGINX Plus instance, with `/_codexch` as the path, e.g. `https://my-nginx.example.com/_codexch`
    * Ensure NGINX Plus is configured as a confidential client (with a client secret)
    * Make a note of the `client ID` and `client secret`
    * Download the `jwks_uri` JWK file to your NGINX Plus instance
    
  * Obtain the URL for the **authorization endpoint**
  
  * Obtain the URL for the **token endpoint**

## Configuring NGINX Plus

Review the following files copied from the GitHub repository so that they match your IdP configuration.

  * **frontend.conf** - this is the reverse proxy configuration and where the IdP is configured
    * Modify the upstream group to match your backend site or app
    * Configure the preferred listen port and [enable SSL/TLS configuration](https://docs.nginx.com/nginx/admin-guide/security-controls/terminating-ssl-http/)
    * Set the value of `$oidc_jwt_keyfile` to match the downloaded JWK file from the IdP and ensure that it is readable by the NGINX worker processes
    * Modify all of the `set $oidc_` directives to match your IdP configuration
    * Set a unique value for `$oidc_hmac_key` to ensure nonce values are unpredictable

  * **openid_connect.server_conf** - this is the NGINX configuration for handling the various stages of OpenID Connect authorization code flow
    * Modify the `add_header Set-Cookie` directives with appropriate [cookie flags](https://en.wikipedia.org/wiki/HTTP_cookie#Terminology) to control the scope of single sign-on and security options, e.g. Domain; Path; Secure;
    * Modify the `resolver` directive to match a DNS server that is capable of resolving the IdP defined in `$oidc_token_endpoint`

  * **openid_connect.js** - this is the JavaScript code for performing the authorization code exchange and nonce hashing
    * No changes are required unless modifying the code exchange or validation process

## Support

The reference OpenID Connect implementation at the root of the GitHub repository is supported for NGINX Plus subscribers.

## Other use cases

Subdirectories within the GitHub repository contain sample implementations for alternative OpenID Connect use cases. These are not supported.

  * **opaque_session_token** - proof of concept implementation that sends a random string to the client rather than the JWT
