package uk.co.getsotto.protocolgate;

import java.net.URI;
import java.net.http.HttpClient;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.time.Duration;
import java.util.Base64;
import java.util.List;

import javax.net.ssl.SNIHostName;
import javax.net.ssl.SSLParameters;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

record ProtocolFixture(URI issuer, URI callback, String clientId, ECKey deploymentKey) {

    static final JsonMapper JSON = JsonMapper.builder().build();

    static ProtocolFixture load() {
        String connection = System.getProperty("sotto.protocol.connection");
        if (connection == null) {
            throw new IllegalStateException("Run scripts/run-protocol-gate to start the Sotto fixture");
        }
        try {
            JsonNode metadata = JSON.readTree(Files.readString(Path.of(connection)));
            URI issuer = URI.create(metadata.required("issuer").asString());
            URI callback = URI.create(metadata.required("callback").asString());
            if (!"https".equals(issuer.getScheme()) || !"localhost".equals(issuer.getHost())
                    || !"http".equals(callback.getScheme()) || !"127.0.0.1".equals(callback.getHost())
                    || callback.getPort() < 1 || !"/login/oauth2/code/sotto".equals(callback.getPath())) {
                throw new IllegalArgumentException("Expected the loopback Sotto issuer and Spring callback");
            }
            String clientId = metadata.required("client_id").asString();
            Path key = Path.of(metadata.required("deployment_key_path").asString());
            KeyFactory factory = KeyFactory.getInstance("EC");
            var privateKey = (ECPrivateKey) factory.generatePrivate(new PKCS8EncodedKeySpec(pem(key, "PRIVATE KEY")));
            // The pinned Rust harness writes the matching public key beside the private key.
            Path publicKeyFile = key.resolveSibling("deployment.pub.pem");
            var publicKey = (ECPublicKey) factory.generatePublic(new X509EncodedKeySpec(pem(publicKeyFile, "PUBLIC KEY")));
            ECKey deploymentKey = new ECKey.Builder(Curve.P_256, publicKey)
                    .privateKey(privateKey)
                    .algorithm(JWSAlgorithm.ES256)
                    .keyID(clientId)
                    .build();
            return new ProtocolFixture(issuer, callback, clientId, deploymentKey);
        }
        catch (Exception failure) {
            throw new IllegalStateException("Could not load the local Sotto protocol fixture", failure);
        }
    }

    URI endpoint(String path) {
        return URI.create(issuer.toASCIIString() + path);
    }

    HttpClient httpClient() {
        // JSSE leaves SNI unset for localhost by default. The fixture Caddy instance
        // uses SNI to choose its certificate, so send it explicitly for the test.
        SSLParameters parameters = new SSLParameters();
        parameters.setServerNames(List.of(new SNIHostName(issuer.getHost())));
        return HttpClient.newBuilder().sslParameters(parameters).connectTimeout(Duration.ofSeconds(5)).build();
    }

    private static byte[] pem(Path path, String label) throws Exception {
        String data = Files.readString(path)
                .replace("-----BEGIN " + label + "-----", "")
                .replace("-----END " + label + "-----", "");
        return Base64.getMimeDecoder().decode(data);
    }
}
