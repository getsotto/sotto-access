# Contributing to Sotto Access

Install the [local build prerequisites](README.md#run-locally) and run `./mvnw verify` before opening a pull request. On Windows, use `.\mvnw.cmd verify`. CI uses the same build.

Sotto Access owns requests and review history. Sotto is the authority for identities, organisation roles, and grants. Keep integration changes compatible with the Sotto interface they consume, and use fixture identities and keys in tests.
