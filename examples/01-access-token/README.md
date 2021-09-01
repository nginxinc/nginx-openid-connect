# NGINX OpenID Connect - Access Token

Reference implementation of NGINX Plus as relying party for OpenID Connect authentication with access token.

## Creating a Docker Image of NGINX Plus
- Create a [Dockerfile](./Dockerfile).
- Download your version of the nginx-repo.crt and nginx-repo.key files via the [customer portal](https://cs.nginx.com/?_ga=2.268586425.912746048.1620625839-85838359.1596947109).

## Create Docker Network
- Create a user-defined bridge network:
  ```bash
  $ docker network create my-net
  ```

## Start IDP such as Keycloak
- From a terminal start Keycloak with the following command:
  ```bash
  $ docker run --name my-idp --network my-net \
               -p 8080:8080                   \
               -e KEYCLOAK_USER=admin         \
               -e KEYCLOAK_PASSWORD=admin     \
               -d jboss/keycloak
  ```

- Execute the following command if you want to stop and remove the container:
  ```bash
  $ docker stop my-idp; docker rm my-idp
  ```

## Creating Docker Image for NGINX Plus w/ OIDC
- Create a Docker image called `nginxoidc`:
  ```bash
  $ docker build --no-cache -t nginxoidc .
  ```

- Create a container named my-apigw based on this image:
  ```bash
  $ docker run  --name my-apigw --network my-net  \
                -p 443:443 -p 8090:8090           \
                --link my-idp:my-idp              \
                -d nginxoidc
  ```

- Execute the following command if you want to stop and remove the container:
  ```bash
  $ docker stop my-apigw; docker rm my-apigw
  ```

## Reference
- [NGINX OpenID Connect](https://github.com/shawnhankim/nginx-openid-connect)
- [Keycloak on Docker](https://www.keycloak.org/getting-started/getting-started-docker)
- [Enabling Single Sign-On for Proxied Applications](https://docs.nginx.com/nginx/deployment-guides/single-sign-on/)
