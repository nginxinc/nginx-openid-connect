# Prerequisites for Testing NGINX Plus OIDC

This doc provides what to configure prior to executing your NGINX Plus for testing OIDC:

- [Configure Your IDP](#configure-your-idp)
- [Prepare Your Certificates & License](#prepare-your-certificates-and-nginx-plus-license)
- [Update OIDC Configurations](#update-oidc-configurations)


## Configure Your IDP
You could find the following guidelines how to configure your IdP.
- [GitHub: NGINX Plus Open ID Connect](https://github.com/nginxinc/nginx-openid-connect/#configuring-your-idp)
- [NGINX Doc: Enabling Single Sign-on for Proxied Applications w/ NGINX Plus](https://docs.nginx.com/nginx/deployment-guides/single-sign-on/)


## Prepare Your Certificates and NGINX Plus License
Let's create your certificates for SSL and download NGINX Plus license files.

**Certificates**:

Create your certificates and copy the files to the following path if you want to enable SSL.
- [**Path**](../build-context/ssl): `build-context/ssl`
- **Files**: `my-sample.crt`, `my-sample.key`
- The certificate files would be copied into your Docker container when you run the Docker.
- If you want to change the file name or type (e.g. `xxx.pem`), you can additionally update the configuration in the [frontend.conf](../build-context/nginx/conf.d/sample_frontend_api_server.conf) .


**NGINX Plus License:**

- Download your version of the `nginx-repo.crt` and `nginx-repo.key` files via the [F5/NGINX customer portal](https://cs.nginx.com/?_ga=2.268586425.912746048.1620625839-85838359.1596947109).
- [**Path**](../build-context/ssl): `build-context/ssl`
- The license files would be copied into your Docker container when you run the Docker.


## Update OIDC Configurations

- Update OIDC configuration in your NGINX Plus config files:
  Category                  | Content                 | Link
  --------------------------|-------------------------|---------
  Frontend/API Server       |  server_name, port, SSL | [Click](../build-context/nginx/conf.d/sample_frontend_api_server.conf)
  OIDC Common Configuration | `$oidc_authz_endpoint`  | [Click](../build-context/nginx/conf.d/oidc_common.conf#L7)
  []()                      | `$oidc_token_endpoint`  | [Click](../build-context/nginx/conf.d/oidc_common.conf#L14)
  []()                      | `$oidc_jwt_keyfile`     | [Click](../build-context/nginx/conf.d/oidc_common.conf#L20)
  []()                      | `$oidc_client`          | [Click](../build-context/nginx/conf.d/oidc_common.conf#L26)
  []()                      | `$oidc_client_secret`   | [Click](../build-context/nginx/conf.d/oidc_common.conf#L36)

- Update a [Dockerfile](../docker/nginxplus-debian/Dockerfile) if you need anything.
  - The `vi` is added for you to easily edit `nginx.conf` for your local testing.
- Edit `/etc/hosts` file with the server name in your local machine like:
  ```
  127.0.0.1      mynginxoidc.aws
  ```

## Install Docker Compose
- [Docker Docs: How to Install Docker Compose](https://docs.docker.com/compose/install/)
