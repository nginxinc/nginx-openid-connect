# Local Setup w/ NGINX Plus API Gateway and Keycloak (TBD)
This doc provides how to locally set up Keycloak and API Gateway using Dockerfile.

- Create a user-defined bridge network:
  ```bash
  $ docker network create my-net
  ```

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

- Create a Docker image called `nginxoidc`:
  ```bash
  $ docker build --no-cache -t nginxoidc .
  ```

- Create a container named my-apigw based on this image:
  ```bash
  $ docker run  --name my-apigw --network my-net              \
                -p 80:80 -p 443:443 -p 8010:8010 -p 9090:9090 \
                --link my-idp:my-idp                          \
                -d nginxoidc
  ```

- Execute the following command if you want to stop and remove the container:
  ```bash
  $ docker stop my-apigw; docker rm my-apigw
  ```

## Reference
- [Keycloak on Docker](https://www.keycloak.org/getting-started/getting-started-docker)
