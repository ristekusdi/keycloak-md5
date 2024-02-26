# keycloak-md5
Add MD5 hashing support to Keycloak.

## Requirements

- Java 11
- Maven 3.9.6

## Building

- Run `mvn package`
- It should generate a JAR archive under `./target/keycloak-md5.jar`

## Deploying to Keycloak

1. Move the built JAR file to Keycloak's directory `standalone/deployments/` (on Keycloak under Docker: `/opt/keycloak/providers`)
2. Watch the `standalone/deployments/` for the file `keycloak-md5.jar.deployed`

:warning: If you find instead the file `keycloak-md5.jar.failed`, you can run the command `cat keycloak-md5.jar.failed` to find out what went wrong with your deployment.
