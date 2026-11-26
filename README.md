# Sotto Access

An open-source companion service for requesting and reviewing access to [Sotto](https://github.com/getsotto/sotto) environments. Sotto Access will own requests and review history. Sotto owns identity, organisation membership, and environment grants.

The project is in early development. The initial build starts the Spring Boot service and serves a health endpoint.

## Run locally

Use JDK 25. The Maven Wrapper downloads and verifies the pinned Maven version on first use. On macOS and Linux, install `unzip` so the wrapper can extract the pinned ZIP archive.

```sh
./mvnw verify
./mvnw spring-boot:run
```

On Windows, use `.\mvnw.cmd` in place of `./mvnw`. While the service is running, check its health from another terminal.

```sh
curl --fail http://localhost:8080/actuator/health
```

See [the contribution guide](CONTRIBUTING.md) for build and test conventions.

## Sotto protocol gate

The opt-in protocol gate runs Spring Security and two Java signing implementations through the pinned Sotto server and Caddy. It uses disposable PostgreSQL, mock sign-in and temporary keys. [Run the protocol gate](docs/protocol-gate.md)

## Licence

Sotto Access is licensed under the [Apache License 2.0](LICENSE).
