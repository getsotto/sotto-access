package uk.co.getsotto.access;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.file.Files;
import java.nio.file.Path;
import java.sql.DriverManager;
import java.sql.SQLException;
import java.time.Duration;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.boot.web.server.context.WebServerApplicationContext;
import org.springframework.context.ConfigurableApplicationContext;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.testcontainers.utility.MountableFile;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class ApplicationPostgresIT {

    private static final String USER = "sotto_access";
    private static final String PASSWORD = "test-access";
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer(
            "postgres@sha256:07abc3f43c9395b0bdbbab36bc25ddb0e8d83cd4fcafb5fb7d6abe14ff156dd8")
            .withUsername("postgres")
            .withDatabaseName("postgres")
            .withEnv("ACCESS_DB_PASSWORD", PASSWORD)
            .withCopyFileToContainer(MountableFile.forHostPath("scripts/provision-access.sql"),
                    "/docker-entrypoint-initdb.d/10-access.sql");

    @BeforeAll
    static void startPostgres() throws Exception {
        POSTGRES.start();
        var result = POSTGRES.execInContainer("psql", "-U", "postgres", "-d", "postgres",
                "-v", "ON_ERROR_STOP=1",
                "-c", "CREATE DATABASE sotto",
                "-c", "REVOKE CONNECT, TEMPORARY ON DATABASE sotto FROM PUBLIC");
        assertThat(result.getExitCode()).as(result.getStderr()).isZero();
    }

    @AfterAll
    static void stopPostgres() {
        POSTGRES.stop();
    }

    @Test
    void migratesItsSchemaAndServesTheBrowserShell() throws Exception {
        try (var application = start();
                var client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(5)).build()) {
            int port = ((WebServerApplicationContext) application).getWebServer().getPort();
            URI origin = URI.create("http://127.0.0.1:" + port);

            var page = get(client, origin.resolve("/"));
            assertThat(page.statusCode()).isEqualTo(200);
            assertThat(page.headers().firstValue("Content-Type")).hasValueSatisfying(
                    value -> assertThat(value).startsWith("text/html"));
            assertThat(page.body()).contains("<h1>Sotto Access</h1>", "href=\"/css/access.css\"");

            var stylesheet = get(client, origin.resolve("/css/access.css"));
            assertThat(stylesheet.statusCode()).isEqualTo(200);
            assertThat(stylesheet.headers().firstValue("Content-Type")).hasValueSatisfying(
                    value -> assertThat(value).startsWith("text/css"));

            var health = get(client, origin.resolve("/actuator/health"));
            assertThat(health.statusCode()).isEqualTo(200);
            assertThat(health.body()).contains("\"status\":\"UP\"");

            try (var connection = DriverManager.getConnection(databaseUrl("sotto_access"), USER, PASSWORD);
                    var statement = connection.createStatement();
                    var rows = statement.executeQuery("""
                            SELECT installed_by FROM access.flyway_schema_history
                            WHERE version = '1' AND success
                            """)) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getString("installed_by")).isEqualTo(USER);
            }
        }
    }

    @Test
    void accessRoleCannotConnectToTheSottoDatabase() {
        assertThatThrownBy(() -> {
            try (var connection = DriverManager.getConnection(databaseUrl("sotto"), USER, PASSWORD)) {
                assertThat(connection.isClosed()).isFalse();
            }
        }).isInstanceOfSatisfying(SQLException.class, failure -> {
            assertThat(failure.getSQLState()).isEqualTo("42501");
            assertThat(failure.getMessage()).contains("permission denied for database", "sotto");
        });
    }

    @Test
    void failedMigrationPreventsStartup(@TempDir Path migrations) throws Exception {
        Files.writeString(migrations.resolve("V2__broken.sql"), "SELECT missing_migration_function();");
        assertThatThrownBy(() -> {
            try (var application = start("--spring.flyway.locations=classpath:db/migration,filesystem:" + migrations)) {
                assertThat(application.isActive()).isTrue();
            }
        }).hasStackTraceContaining("V2__broken.sql")
                .hasStackTraceContaining("missing_migration_function");
    }

    private static ConfigurableApplicationContext start(String... extra) {
        var args = new ArrayList<>(List.of(
                "--server.address=127.0.0.1",
                "--server.port=0",
                "--spring.datasource.url=" + databaseUrl("sotto_access"),
                "--spring.datasource.username=" + USER,
                "--spring.datasource.password=" + PASSWORD));
        args.addAll(Arrays.asList(extra));
        return new SpringApplicationBuilder(SottoAccessApplication.class).run(args.toArray(String[]::new));
    }

    private static String databaseUrl(String name) {
        return "jdbc:postgresql://" + POSTGRES.getHost() + ":" + POSTGRES.getMappedPort(5432) + "/" + name;
    }

    private static HttpResponse<String> get(HttpClient client, URI url) throws Exception {
        var request = HttpRequest.newBuilder(url).timeout(Duration.ofSeconds(5)).GET().build();
        return client.send(request, HttpResponse.BodyHandlers.ofString());
    }
}
