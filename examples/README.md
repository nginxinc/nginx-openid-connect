# NGINX OpenID Connect: Examples

This directory provides the examples of [NGINX configuration](./build-context/nginx/conf.d), [Dockerfile](./docker/nginxplus-debian/Dockerfile) and [OIDC codebase](./build-context/nginx/conf.d/oidc.js) that contain enhanced features such as additional access token, user information and log-in/out by refactoring the [nginx-openid-connect](https://github.com/nginxinc/nginx-openid-connect).


## Prerequisites
Let's find [this guideline](./docs/prerequisites.md) to check what to configure prior to executing your NGINX Plus for testing OIDC:


## Set Up Local NGINX Plus Docker
Let's set up your local environment for testing OIDC workflows based on NGINX Plus docker container as follows.

**Create a Docker image called `nginxplus-oidc-debian`**:
```
$ docker-compose build --no-cache
```

**Clean out old images and volumes** if you want:
```
$ docker system prune -a && \
  docker volume rm $(docker volume ls -qf dangling=true)
```

**Run a Docker container based on the image:**
```bash
$ NGINX_CONF_PATH=/Users/{your user name}/{your github path}/nginx-openid-connect/examples/context/nginx/conf.d
$ docker-compose up -d
```

**Execute the following command if you want to stop the container:**
```bash
$ docker-compose down
```

## Test OIDC Use Cases
You could find how to locally test OIDC use cases as the following table.

Use Cases                       | How To Test
--------------------------------|-----------------------------------------------
Access Web Page with OIDC       | [Access web page based on OIDC workflow](./use-case/01-access-web-and-tokens/README.md#access-web-page-with-nginx-oidc)
ID & Access Token               | [Retrieve ID / Access token from the IdP](./use-case/01-access-web-and-tokens/README.md#query-current-sessions)
Access Token to Proxied Backend | [Pass bearer access token to proxied backend](./use-case/01-access-web-and-tokens/README.md#vall-proxied-backend-service-with-access-token)
User Information                | [Retrieve user info from the IdP using bearer access token](./use-case/02-user-info/README.md)
Login                           | Log-in via the IdP (TBD).
Logout                          | Log-out via web page (TBD).
Refresh Token                   | Update and retrieve ID / Access token via refresh token (TBD).

## Reference
- [NGINX OpenID Connect](https://github.com/shawnhankim/nginx-openid-connect)
- [Enabling Single Sign-On for Proxied Applications](https://docs.nginx.com/nginx/deployment-guides/single-sign-on/)
- [OpenID Connect Core 1.0](https://openid.net/specs/openid-connect-core-1_0.html)
  - [OIDC Token Request](http://openid.net/specs/openid-connect-core-1_0.html#TokenRequest)
  - [Refresh Access Token](https://openid.net/specs/openid-connect-core-1_0.html#RefreshingAccessToken)
  - [Refresh Error Response](https://openid.net/specs/openid-connect-core-1_0.html#RefreshErrorResponse)
  - [Successful Refresh Response](https://openid.net/specs/openid-connect-core-1_0.html#RefreshTokenResponse)
  - [ID Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#IDTokenValidation)
  - [Access Token Validation](https://openid.net/specs/openid-connect-core-1_0.html#CodeFlowTokenValidation)
- [RFC7519: JWT Claims](https://datatracker.ietf.org/doc/html/rfc7519#page-8)
