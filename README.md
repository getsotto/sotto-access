# Sotto Access

An open-source companion service for requesting and reviewing access to [Sotto](https://github.com/getsotto/sotto) environments. Sotto Access will own requests and review history. Sotto owns identity, organisation membership, and environment grants.

The project is in early development. Spring Boot 4.2.0 serves a Thymeleaf browser shell and a health endpoint. Flyway migrates the Access schema on startup.

## Run locally

Use JDK 25 and Docker with Compose. The Maven Wrapper downloads and verifies Maven 3.9.16 on first use. On macOS and Linux, install `unzip` so the wrapper can extract the pinned ZIP archive.

```sh
./mvnw verify
docker compose up --wait postgres
export SPRING_DATASOURCE_URL=jdbc:postgresql://127.0.0.1:55432/sotto_access
export SPRING_DATASOURCE_USERNAME=sotto_access
export SPRING_DATASOURCE_PASSWORD=local-access
./mvnw spring-boot:run
```

On Windows, use `.\mvnw.cmd` in place of `./mvnw` and PowerShell's `$env:NAME = 'value'` syntax for the variables. Open [the local application](http://localhost:8080/) or check its health from another terminal.

```sh
curl --fail http://localhost:8080/actuator/health
```

The Compose service uses development credentials and keeps its database in a named volume. Use `docker compose stop postgres` to stop it and retain the data.

The build produces an executable Spring Boot JAR. Run it with `java -jar target/sotto-access-0.1.0-SNAPSHOT.jar` and the same datasource variables.

See [the contribution guide](CONTRIBUTING.md) for test conventions and [database setup](docs/database.md) for a separate Access role and database on an existing PostgreSQL server.

## Sotto protocol gate

The opt-in protocol gate runs Spring Security and two Java signing implementations through the pinned Sotto server and Caddy. It uses disposable PostgreSQL, mock sign-in and temporary keys. [Run the protocol gate](docs/protocol-gate.md)

## Licence

Sotto Access is licensed under the [Apache License 2.0](LICENSE).
