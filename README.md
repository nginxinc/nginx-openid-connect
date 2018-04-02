# nginx-openid-connect

Reference implementation of NGINX Plus as relying party for OpenID Connect authentication

## Description

Implements OpenID Connect 1.0 authorization code flow with NGINX Plus as the relying party for confidential clients.

`[diagram of components (client, IdP, NGINX Plus, backend)]`

`[OIDC protocol diagram]`

NGINX Plus is configured to perform OpenID Connect authentication. Upon a first visit to a protected resource, NGINX Plus initiates the OpenID Connect authorization code flow and redirects the client to the OpenID Connect provider (IdP). When the client returns to NGINX Plus with an authorization code, NGINX Plus exchanges that code for a set of tokens by communicating directly with the IdP.

The ID Token received from the IdP is then [validated](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation). NGINX Plus then issues a session cookie to the client using either the ID Token or the Access Token and is redirected to the original URI requested prior to authentication.

Subsequent requests to protected resources are authenticated using the session cookie by performing JWT validation.
 
For more information on OIDC and NGINX Plus JWT support, see [Authenticating Users to Existing Applications with OpenID Connect and NGINX Plus](https://www.nginx.com/blog/authenticating-users-existing-applications-openid-connect-nginx-plus/).

## Installation

OpenID Connect integration requires NGINX Plus R15 or later to be installed. See [Installing NGINX Plus](https://docs.nginx.com/nginx/admin-guide/installing-nginx/installing-nginx-plus/).

In addition, the nginScript module is required for handling the interaction between NGINX Plus and the OpenID Connect provider (IdP). Install the nginScript module after installing NGINX Plus by running one of the following:

`$ sudo apt install nginx-plus-module-njs` for Debian/Ubuntu

`$ sudo yum install nginx-plus-module-njs` for CentOS/RedHat

The nginScript module needs to be loaded by adding the following configuration directive near the top of **nginx.conf**.

<pre>load_module modules/ngx_http_js_module.so;</pre>

Finally, create a clone of the GitHub repository.

`$ git clone https://github.com/nginxinc/nginx-openid-connect`

All files can be copied to **/etc/nginx/conf.d**

## Configuring NGINX Plus as a Relying Party

The GitHub repository contains [include](http://nginx.org/en/docs/ngx_core_module.html#include) files for NGINX configuration and JavaScript code for token exchange and initial token validation. Some configuration is required:

  * **frontend.conf** - this is the reverse proxy configuration and where the IdP is configured
    * Modify the upstream group to match your backend site or app
    * Configure the preferred listen port and enable SSL/TLS configuration
    * Modify all of the `set $oidc_` directives to match your IdP.
    * Set a unique value for $oidc_hmac_key to ensure unpredicatable nonce

  * **openid_connect.server_conf** - this is the NGINX configuration for handling the various stages of OpenID Connect authorization code flow
    * Modify the `add_header Set-Cookie` directives with appropriate cookie flags, e.g. Domain; Path; Secure;
    * Modify the `resolver` directive to match a DNS server that is capable of resolving the IdP defined in `$oidc_token_endpoint`

  * **openid_connect.js** - this is the nginScript code for performing the authorization code exchange and nonce hashing
    * No changes are required unless modifying the code exchange process

## TO DO
  * ID Token validation of iss value
  * Dynamic state value
  * Opaque session cookie
  * UserInfo implementation
