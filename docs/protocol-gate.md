# Sotto protocol gate

The gate exercises Sotto sign-in and signed deployment requests over the self-hosted Caddy routes. The Maven profile starts a Spring Boot test application on loopback and runs against the Rust fixture from Sotto. The default build packages the service and runs the health test. CI also compiles the gate profile.

## Run locally

Use JDK 25, Git, Rust, Python 3, Docker, OpenSSL 3 or later and a Caddy binary built with Sotto's rate limit module. To build the matching Caddy version, install Go and run the following.

```sh
go run github.com/caddyserver/xcaddy/cmd/xcaddy@v0.4.7 build v2.11.9 \
  --with github.com/mholt/caddy-ratelimit@v0.1.0 --output /tmp/sotto-fixture-caddy
```

Check out the pinned Rust revision, then run the gate from the Access checkout.

```sh
git clone https://github.com/getsotto/sotto.git /tmp/sotto-protocol-gate
git -C /tmp/sotto-protocol-gate checkout --detach eb9a874ed16f046f1ac31e74bd1af9e5003a3f5a
scripts/run-protocol-gate /tmp/sotto-protocol-gate /tmp/sotto-fixture-caddy
```

The runner builds the fixture with the checked-in Cargo lockfile and fetches PostgreSQL 16.16 by its multi-platform digest `sha256:07abc3f43c9395b0bdbbab36bc25ddb0e8d83cd4fcafb5fb7d6abe14ff156dd8`. It registers a temporary loopback callback and creates a JVM trust store from Caddy's fixture certificate. The Rust runner creates the database, mock identity and signing keys. The two runners remove the fixture processes, database container and temporary files when the run finishes or is cancelled. [Sotto fixture image option](https://github.com/getsotto/sotto/pull/916)

## Observed protocol

| Exchange | Verified behaviour |
| --- | --- |
| Sign-in | Spring Security 7.2.0 on Spring Boot 4.2.0 completes Authorization Code Flow with S256 PKCE. The emitted `private_key_jwt` uses ES256 with the discovery issuer as its sole audience. Spring defaults to the token endpoint audience, so the gate sets the issuer explicitly. The Access browser session returns the issuer and Sotto user ID observed at `/auth/me`. |
| Deployment proof | Authlete HTTP Message Signatures 1.8 and the JDK 25 P1363 ECDSA reference both pass the same wire tests. Both use `ecdsa-p256-sha256` and the fixture deployment key. |
| Covered components | The POST signs `@method`, `@target-uri` and `content-digest` in that order. The digest is SHA-256 over the exact bytes sent. The GET signs `@method` and `@target-uri` and sends an empty body. |
| Proxy | The client signs the external HTTPS authority, path and query. Caddy uses Sotto's OAuth route matcher and forwards the original path and query. The fixture reconstructs the target from its configured external origin and the original path and query. The signed status query succeeds. A request signed for a different host still fails when it supplies that host in forwarding headers. |
| Retry | The client signs proofs for 60 seconds with a fresh nonce and the registered key ID. The fixture rejects expired and repeated proofs. A fresh proof for the same attempt returns the same connection ID. The signed status lookup returns that receipt. |

Authlete is the Java signing candidate for the production slices. It constructs and serialises the signature base and fields, and delegates ES256 to Nimbus JOSE + JWT. The gate pins Nimbus 10.9.1, matching Spring Security, and resolves Authlete's structured fields dependency at 0.4. The JDK comparison serialises the fixed fixture profile directly and signs it with `SHA256withECDSAinP1363Format`. [Authlete HTTP Message Signatures](https://github.com/authlete/http-message-signatures) · [RFC 9421](https://www.rfc-editor.org/rfc/rfc9421.html) · [RFC 9530](https://www.rfc-editor.org/rfc/rfc9530.html)

The test transport explicitly sends `localhost` as its TLS server name because the pinned Caddy fixture selects its certificate by that name. Java verifies the hostname and certificate against the temporary trust store. Spring uses that transport for discovery, token exchange and key retrieval.

## Verification

The original Java gate at `44bbefe8e8298779b8ee7dffbeabe48003d047a4` ran from a fresh Access checkout with OpenJDK 25.0.3, disposable PostgreSQL 16.16 and Caddy 2.11.9 against Sotto `a373d372c6119fafe779c899af29b8a9eaed3da5`. Spring sign-in and both signing implementations passed. Removing the audience override or excluding the digest from a POST signature individually failed the corresponding Java test. The restored gate passed again.

Run the Rust check on its own from the pinned Sotto checkout after the Java gate builds the fixture.

```sh
scripts/access-protocol-fixture --server target/debug/sotto-server \
  --caddy /tmp/sotto-fixture-caddy \
  --postgres-image postgres@sha256:07abc3f43c9395b0bdbbab36bc25ddb0e8d83cd4fcafb5fb7d6abe14ff156dd8 --check
```
