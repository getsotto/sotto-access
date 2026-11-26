package uk.co.getsotto.protocolgate;

import java.net.URI;
import java.net.http.HttpRequest;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.Signature;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import com.authlete.hms.ComponentIdentifier;
import com.authlete.hms.ComponentValueProvider;
import com.authlete.hms.SignatureBaseBuilder;
import com.authlete.hms.SignatureField;
import com.authlete.hms.SignatureInputField;
import com.authlete.hms.SignatureMetadata;
import com.authlete.hms.SignatureMetadataParameters;
import com.authlete.hms.impl.JoseHttpSigner;
import com.nimbusds.jose.jwk.ECKey;

record DeploymentProof(String input, String signature, String digest) {

    private static final String LABEL = "access";
    private static final String ALGORITHM = "ecdsa-p256-sha256";

    enum Signer {
        AUTHLETE, JDK
    }

    static DeploymentProof sign(Signer implementation, ECKey key, String method, URI target, byte[] body,
            Instant created) throws Exception {
        String digest = body == null ? null
                : "sha-256=:" + Base64.getEncoder().encodeToString(MessageDigest.getInstance("SHA-256").digest(body)) + ":";
        String nonce = UUID.randomUUID().toString();
        Instant expires = created.plusSeconds(60);
        return switch (implementation) {
            case AUTHLETE -> authlete(key, method, target, digest, created, expires, nonce);
            case JDK -> jdk(key, method, target, digest, created, expires, nonce);
        };
    }

    void addTo(HttpRequest.Builder request) {
        request.header("Signature-Input", input).header("Signature", signature);
        if (digest != null) {
            request.header("Content-Digest", digest);
        }
    }

    private static DeploymentProof authlete(ECKey key, String method, URI target, String digest, Instant created,
            Instant expires, String nonce) throws Exception {
        var values = new ComponentValueProvider().setMethod(method).setTargetUri(target);
        var methodComponent = new ComponentIdentifier("@method");
        var targetComponent = new ComponentIdentifier("@target-uri");
        var components = digest == null ? List.of(methodComponent, targetComponent)
                : List.of(methodComponent, targetComponent, new ComponentIdentifier("content-digest"));
        if (digest != null) {
            values.setHeaders(Map.of("content-digest", List.of(digest)));
        }
        var parameters = new SignatureMetadataParameters()
                .setCreated(created)
                .setKeyid(key.getKeyID())
                .setAlg(ALGORITHM)
                .setNonce(nonce)
                .setExpires(expires);
        var metadata = new SignatureMetadata(components, parameters);
        byte[] bytes = new SignatureBaseBuilder(values).build(metadata).sign(new JoseHttpSigner(key));
        return new DeploymentProof(new SignatureInputField(Map.of(LABEL, metadata)).serialize(),
                new SignatureField(Map.of(LABEL, bytes)).serialize(), digest);
    }

    private static DeploymentProof jdk(ECKey key, String method, URI target, String digest, Instant created,
            Instant expires, String nonce) throws Exception {
        // An independent comparison for this fixture's fixed component set. The JDK handles
        // the ECDSA operation, while Authlete also handles RFC 9421 field serialization.
        String covered = digest == null ? "\"@method\" \"@target-uri\""
                : "\"@method\" \"@target-uri\" \"content-digest\"";
        String parameters = "(%s);created=%d;expires=%d;nonce=\"%s\";keyid=\"%s\";alg=\"%s\""
                .formatted(covered, created.getEpochSecond(), expires.getEpochSecond(), nonce, key.getKeyID(), ALGORITHM);
        String digestLine = digest == null ? "" : "\n\"content-digest\": " + digest;
        String base = "\"@method\": %s\n\"@target-uri\": %s%s\n\"@signature-params\": %s"
                .formatted(method, target.toASCIIString(), digestLine, parameters);
        Signature signer = Signature.getInstance("SHA256withECDSAinP1363Format");
        signer.initSign(key.toECPrivateKey());
        signer.update(base.getBytes(StandardCharsets.US_ASCII));
        return new DeploymentProof(LABEL + "=" + parameters,
                LABEL + "=:" + Base64.getEncoder().encodeToString(signer.sign()) + ":", digest);
    }
}
