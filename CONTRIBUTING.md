# Contributing to Sotto Access

Install the [local build prerequisites](README.md#run-locally) and run `./mvnw verify` before opening a pull request. On Windows, use `.\mvnw.cmd verify`. CI uses the same build.

`./mvnw test` runs the unit test phase. `./mvnw verify` also runs the Failsafe integration tests in `ApplicationPostgresIT` against disposable PostgreSQL 16.16 using Testcontainers 2.0.5. Docker must be available to run them. The test output and `target/failsafe-reports` identify the database tests. The `protocol-gate` profile runs its cross-repository integration tests separately.

Add ordered SQL migrations under `src/main/resources/db/migration`. Keep applied migrations immutable so Flyway can validate them at startup.

Sotto Access owns requests and review history. Sotto is the authority for identities, organisation roles, and grants. Keep integration changes compatible with the Sotto interface they consume, and use fixture identities and keys in tests.
