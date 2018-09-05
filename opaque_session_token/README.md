## Opaque Session Token

This is a variation on the reference implementation of NGINX Plus as relying party for OpenID Connect authentication.

## Description

This use case varies from the top-level reference implementation at the step when the ID Token received from the IdP. Instead of sending the ID Token to the client as a session cookie, the ID Token is saved to the NGINX Plus [key-value store](http://nginx.org/en/docs/http/ngx_http_keyval_module.html). A random string is sent to the client as the session cookie and acts as the _key_ to the key-value store.

Subsequent requests to protected resources are authenticated by exchanging the session cookie for the ID Token in the key-value store. JWT validation is performed on each request, as normal, so that the ID Token validity period is enforced.

## Installation

OpenID Connect with Opaque Session Token requires NGINX Plus R16 or later to be installed. Installation is as per the instructions in the top-level of the GitHub repo, and using the files found in this directory.

## Configuration

Configuration is as per the instructions in the top-level of the GitHub repo. The key-value store may additionally be configured, within **frontend.conf**, e.g.:

```nginx
keyval_zone zone=sessions:1M state=state_sessions.json timeout=601m sync;
```

Each of the `keyval_zone` parameters are described below.

  * **zone** - Specifies the name of the key-value store and how much memory to allocate for it. Each session will typically occupy 1-2KB, depending on the size of the JWT, so scale this value to exceed the number of unique users that may authenticate.

  * **state** (optional) - Specifies where all of the ID Tokens in the key-value store are saved, so that sessions will persist across restart or reboot of the NGINX host. The NGINX Plus user account, typically **nginx**, must have write permission to the directory where the state file is stored. Consider creating a dedicated directory for this purpose.

  * **timeout** - Expired tokens are removed from the key-value store after the `timeout` value. This should be set to value slightly longer than the JWT validity period. JWT validation occurs on each request, and will fail when the expiry date (`exp` claim) has elapsed. If JWTs are issued without an `exp` claim then set `timeout` to the desired session duration. If JWTs are issued with a range of validity periods then set `timeout` to exceed the longest period.

  * **sync** (optional) - If deployed in a cluster, the key-value store may be synchronized across all instances in the cluster, so that all instances are able to create and validate authenticated sessions. Each instance must be configured to participate in state sharing with the [zone_sync module](http://nginx.org/en/docs/stream/ngx_stream_zone_sync_module.html) and by adding the `sync` parameter to the `keyval_zone` directive above.

## Session Management

The [NGINX Plus API](http://nginx.org/en/docs/http/ngx_http_api_module.html) is enabled in **openid_connect.server_conf** so that sessions can be created. The API can be used to manage the current set of active sessions.

To query the current sessions in the key-value store:

`$ curl localhost:8010/api/3/http/keyvals/sessions`

To delete a single session:

`$ curl -iX PATCH '{"<session ID>":null}' localhost:8010/api/3/http/keyvals/sessions`

To delete all sessions:

`$ curl -iX DELETE localhost:8010/api/3/http/keyvals/sessions`
