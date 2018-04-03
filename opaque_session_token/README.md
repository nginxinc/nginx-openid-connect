## Opaque Session Token

This is a proof of concept implementation of NGINX Plus as relying party for OpenID Connect authentication.

## Description

This is a variation of the reference OpenID Connect implementation. It does not send a JWT to the client as a session cookie. The ID Token is stored in the NGINX Plus key-value store and a random value is sent as a session cookie.

When the client presents the session cookie, that value is used to obtain the ID Token from the key-value store. The ID Token is then validated with `auth_jwt` as usual before the client request is proxied to the backend.

This proof of concept implementation is not suitable for production use because expired tokens are not removed from the key-value store.

To query the current sessions in the key-value store:

`curl localhost:8010/api/3/http/keyvals/sessions`

To delete a single session:

`curl -X PATCH '{"<session ID>":null}' localhost:8010/api/3/http/keyvals/sessions`

To delete all sessions

`curl -X DELETE localhost:8010/api/3/http/keyvals/sessions`
