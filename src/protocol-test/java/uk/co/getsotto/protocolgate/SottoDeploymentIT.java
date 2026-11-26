package uk.co.getsotto.protocolgate;

import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.time.Duration;
import java.time.Instant;
import java.util.Arrays;
import java.util.Map;
import java.util.UUID;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;

import static org.assertj.core.api.Assertions.assertThat;

class SottoDeploymentIT {

    private final ProtocolFixture fixture = ProtocolFixture.load();

    @ParameterizedTest
    @EnumSource(DeploymentProof.Signer.class)
    void verifiesDeploymentProofsAndReturnsTheSameConfirmationOnRetry(DeploymentProof.Signer signer) throws Exception {
        URI confirm = fixture.endpoint("/confirm");
        String attempt = UUID.randomUUID().toString();
        byte[] body = ProtocolFixture.JSON.writeValueAsBytes(Map.of("attempt_id", attempt));
        byte[] changedBody = Arrays.copyOf(body, body.length + 1);
        changedBody[body.length] = ' ';

        try (HttpClient http = fixture.httpClient()) {
            var stale = proof(signer, "POST", confirm, body, Instant.now().minusSeconds(180));
            assertThat(send(http, confirm, "POST", body, stale).statusCode()).as("stale proof").isEqualTo(401);

            var first = proof(signer, "POST", confirm, body, Instant.now());
            URI changedTarget = URI.create(confirm + "?changed=target");
            assertThat(send(http, changedTarget, "POST", body, first).statusCode()).as("changed target").isEqualTo(401);
            assertThat(send(http, confirm, "POST", changedBody, first).statusCode()).as("changed body").isEqualTo(401);

            URI otherOrigin = URI.create("https://different.invalid" + confirm.getRawPath());
            var wrongOrigin = proof(signer, "POST", otherOrigin, body, Instant.now());
            var spoofed = post(confirm, body).header("X-Forwarded-Host", otherOrigin.getHost())
                    .header("Forwarded", "host=different.invalid;proto=https");
            assertThat(send(http, spoofed, wrongOrigin).statusCode()).as("client supplied forwarding host").isEqualTo(401);

            var confirmed = send(http, confirm, "POST", body, first);
            assertThat(confirmed.statusCode()).as("valid body and proof").isEqualTo(200);
            var receipt = ProtocolFixture.JSON.readTree(confirmed.body());
            assertThat(receipt.required("attempt_id").asString()).isEqualTo(attempt);
            assertThat(UUID.fromString(receipt.required("connection_id").asString())).isNotNull();
            assertThat(send(http, confirm, "POST", body, first).statusCode()).as("replay").isEqualTo(401);

            var fresh = proof(signer, "POST", confirm, body, Instant.now());
            var retried = send(http, confirm, "POST", body, fresh);
            assertThat(retried.statusCode()).as("fresh proof for the same attempt").isEqualTo(200);
            assertThat(ProtocolFixture.JSON.readTree(retried.body())).isEqualTo(receipt);

            URI status = fixture.endpoint("/connection-status/" + attempt);
            var wrongMethod = proof(signer, "POST", status, null, Instant.now());
            assertThat(send(http, status, "GET", null, wrongMethod).statusCode()).as("changed method").isEqualTo(401);
            var statusProof = proof(signer, "GET", status, null, Instant.now());
            assertThat(statusProof.digest()).isNull();
            var lookup = send(http, status, "GET", null, statusProof);
            assertThat(lookup.statusCode()).as("bodyless status lookup").isEqualTo(200);
            assertThat(ProtocolFixture.JSON.readTree(lookup.body())).isEqualTo(receipt);
        }
    }

    private DeploymentProof proof(DeploymentProof.Signer signer, String method, URI target, byte[] body, Instant created)
            throws Exception {
        return DeploymentProof.sign(signer, fixture.deploymentKey(), method, target, body, created);
    }

    private static HttpResponse<String> send(HttpClient http, URI target, String method, byte[] body,
            DeploymentProof proof) throws Exception {
        var request = "GET".equals(method) ? HttpRequest.newBuilder(target).GET() : post(target, body);
        return send(http, request, proof);
    }

    private static HttpResponse<String> send(HttpClient http, HttpRequest.Builder request, DeploymentProof proof)
            throws Exception {
        proof.addTo(request);
        return http.send(request.timeout(Duration.ofSeconds(10)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static HttpRequest.Builder post(URI target, byte[] body) {
        return HttpRequest.newBuilder(target).header("Content-Type", "application/json")
                .POST(HttpRequest.BodyPublishers.ofByteArray(body));
    }
}
