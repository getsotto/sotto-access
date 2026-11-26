package uk.co.getsotto.protocolgate;

import java.net.URI;
import java.net.URLDecoder;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.text.ParseException;
import java.time.Duration;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.atomic.AtomicReference;

import com.nimbusds.jwt.SignedJWT;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.autoconfigure.EnableAutoConfiguration;
import org.springframework.boot.jdbc.autoconfigure.DataSourceAutoConfiguration;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Import;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.client.JdkClientHttpRequestFactory;
import org.springframework.http.converter.FormHttpMessageConverter;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.client.endpoint.NimbusJwtClientAuthenticationParametersConverter;
import org.springframework.security.oauth2.client.endpoint.OAuth2AuthorizationCodeGrantRequest;
import org.springframework.security.oauth2.client.endpoint.RestClientAuthorizationCodeTokenResponseClient;
import org.springframework.security.oauth2.client.http.OAuth2ErrorResponseErrorHandler;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenDecoderFactory;
import org.springframework.security.oauth2.client.oidc.authentication.OidcIdTokenValidator;
import org.springframework.security.oauth2.client.registration.ClientRegistration;
import org.springframework.security.oauth2.client.registration.ClientRegistrationRepository;
import org.springframework.security.oauth2.client.registration.ClientRegistrations;
import org.springframework.security.oauth2.client.registration.InMemoryClientRegistrationRepository;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.http.converter.OAuth2AccessTokenResponseHttpMessageConverter;
import org.springframework.security.oauth2.core.oidc.user.OidcUser;
import org.springframework.security.oauth2.jose.jws.SignatureAlgorithm;
import org.springframework.security.oauth2.jwt.JwtDecoderFactory;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import org.springframework.security.web.SecurityFilterChain;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.util.MultiValueMap;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.client.RestClient;
import org.springframework.web.client.RestTemplate;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(classes = SottoSignInIT.TestAccess.class, webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT,
        properties = {
                // RestClient's debug logging includes the token request form.
                "logging.level.org.springframework.web.client=OFF",
                "logging.level.org.springframework.security=INFO"
        })
class SottoSignInIT {

    private static final ProtocolFixture FIXTURE = ProtocolFixture.load();

    @Autowired
    private TokenRequestCapture tokenRequest;

    @DynamicPropertySource
    static void useRegisteredCallback(DynamicPropertyRegistry properties) {
        properties.add("server.address", FIXTURE.callback()::getHost);
        properties.add("server.port", FIXTURE.callback()::getPort);
    }

    @Test
    void establishesAnAccessSessionWithTheSottoIssuerAndSubject() throws Exception {
        try (HttpClient browser = FIXTURE.httpClient()) {
            URI sotto = FIXTURE.issuer().resolve("/");
            var githubLogin = request(browser, sotto.resolve("/auth/github/login?redirect_uri="
                    + encode(sotto.toString()) + "&state=protocol-gate"), null);
            assertThat(githubLogin.statusCode()).isEqualTo(303);
            // Complete the fixture's mock GitHub login without following the GitHub redirect.
            String mockState = query(location(githubLogin)).get("state");
            var githubCallback = request(browser, sotto.resolve("/auth/github/callback?state="
                    + encode(mockState) + "&code=fixture-alice"), null);
            assertThat(githubCallback.statusCode()).isEqualTo(303);
            String sottoCookie = cookie(githubCallback, "sotto_session");
            var account = request(browser, sotto.resolve("/auth/me"), sottoCookie);
            assertThat(account.statusCode()).isEqualTo(200);
            String sottoUser = ProtocolFixture.JSON.readTree(account.body()).required("user_id").asString();
            assertThat(sottoUser).isNotBlank();

            URI access = FIXTURE.callback().resolve("/");
            assertThat(request(browser, access.resolve("/identity"), null).statusCode()).isEqualTo(302);
            var login = request(browser, access.resolve("/oauth2/authorization/sotto"), null);
            assertThat(login.statusCode()).isEqualTo(302);
            String accessCookie = cookie(login, "JSESSIONID");
            URI authorisation = location(login);
            assertThat(authorisation.toString().startsWith(FIXTURE.endpoint("/authorize") + "?")).isTrue();
            Map<String, String> parameters = query(authorisation);
            assertThat(parameters.get("redirect_uri")).isEqualTo(FIXTURE.callback().toString());
            assertThat(parameters.get("code_challenge_method")).isEqualTo("S256");
            assertThat(parameters.get("code_challenge")).isNotBlank();
            assertThat(parameters.get("state")).isNotBlank();
            assertThat(parameters.get("nonce")).isNotBlank();

            var authorised = request(browser, authorisation, sottoCookie);
            assertThat(authorised.statusCode()).isEqualTo(303);
            URI callback = location(authorised);
            assertThat(callback.toString().startsWith(FIXTURE.callback() + "?")).isTrue();
            var signedIn = request(browser, callback, accessCookie);

            TokenRequest observed = tokenRequest.observed.get();
            assertThat(observed).as("Spring token request").isNotNull();
            assertThat(observed.audience()).containsExactly(FIXTURE.issuer().toString());
            assertThat(observed.algorithm()).isEqualTo("ES256");
            assertThat(observed.assertionType()).isEqualTo("urn:ietf:params:oauth:client-assertion-type:jwt-bearer");
            assertThat(observed.challenge()).isEqualTo(parameters.get("code_challenge"));
            assertThat(signedIn.statusCode()).isEqualTo(302);

            // Spring changes the session ID after authenticating the browser.
            String signedInCookie = cookie(signedIn, "JSESSIONID");
            var identity = request(browser, access.resolve("/identity"), signedInCookie);
            assertThat(identity.statusCode()).isEqualTo(200);
            var claims = ProtocolFixture.JSON.readTree(identity.body());
            assertThat(claims.required("issuer").asString()).isEqualTo(FIXTURE.issuer().toString());
            assertThat(claims.required("subject").asString()).isEqualTo(sottoUser);
        }
    }

    private static HttpResponse<String> request(HttpClient browser, URI target, String cookie) throws Exception {
        var request = HttpRequest.newBuilder(target).timeout(Duration.ofSeconds(10)).GET();
        if (cookie != null) {
            request.header("Cookie", cookie);
        }
        return browser.send(request.build(), HttpResponse.BodyHandlers.ofString());
    }

    private static URI location(HttpResponse<?> response) {
        return URI.create(response.headers().firstValue("Location").orElseThrow());
    }

    private static String cookie(HttpResponse<?> response, String name) {
        return response.headers().allValues("Set-Cookie").stream()
                .filter(value -> value.startsWith(name + "="))
                .map(value -> value.split(";", 2)[0])
                .findFirst()
                .orElseThrow(() -> new IllegalStateException("Missing " + name + " cookie"));
    }

    private static Map<String, String> query(URI uri) {
        Map<String, String> result = new HashMap<>();
        for (String field : uri.getRawQuery().split("&")) {
            String[] pair = field.split("=", 2);
            result.put(URLDecoder.decode(pair[0], StandardCharsets.UTF_8),
                    URLDecoder.decode(pair[1], StandardCharsets.UTF_8));
        }
        return result;
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8);
    }

    @Configuration(proxyBeanMethods = false)
    @EnableAutoConfiguration(exclude = DataSourceAutoConfiguration.class)
    @EnableWebSecurity
    @Import(IdentityEndpoint.class)
    static class TestAccess {

        @Bean
        HttpClient sottoHttpClient() {
            return FIXTURE.httpClient();
        }

        @Bean
        JdkClientHttpRequestFactory sottoRequests(HttpClient sottoHttpClient) {
            var factory = new JdkClientHttpRequestFactory(sottoHttpClient);
            factory.setReadTimeout(Duration.ofSeconds(10));
            return factory;
        }

        @Bean
        ClientRegistrationRepository clients(JdkClientHttpRequestFactory sottoRequests) {
            Map<String, Object> metadata = RestClient.builder().requestFactory(sottoRequests).build()
                    .get().uri(FIXTURE.endpoint("/.well-known/openid-configuration")).retrieve()
                    .body(new ParameterizedTypeReference<>() {});
            if (metadata == null || !FIXTURE.issuer().toString().equals(metadata.get("issuer"))) {
                throw new IllegalStateException("The discovery document must identify the configured Sotto issuer");
            }
            ClientRegistration registration = ClientRegistrations.fromOidcConfiguration(metadata)
                    .registrationId("sotto")
                    .clientId(FIXTURE.clientId())
                    .clientAuthenticationMethod(ClientAuthenticationMethod.PRIVATE_KEY_JWT)
                    .redirectUri(FIXTURE.callback().toString())
                    .scope("openid")
                    .clientSettings(ClientRegistration.ClientSettings.builder().requireProofKey(true).build())
                    .build();
            return new InMemoryClientRegistrationRepository(registration);
        }

        @Bean
        JwtDecoderFactory<ClientRegistration> idTokenDecoderFactory(JdkClientHttpRequestFactory sottoRequests) {
            // Use the fixture's TLS transport while retaining Spring's OIDC claim and time validators.
            return registration -> {
                var decoder = NimbusJwtDecoder.withJwkSetUri(registration.getProviderDetails().getJwkSetUri())
                        .restOperations(new RestTemplate(sottoRequests))
                        .jwsAlgorithm(SignatureAlgorithm.ES256)
                        .build();
                decoder.setJwtValidator(JwtValidators.createDefaultWithValidators(new OidcIdTokenValidator(registration)));
                decoder.setClaimSetConverter(OidcIdTokenDecoderFactory.createDefaultClaimTypeConverter());
                return decoder;
            };
        }

        @Bean
        TokenRequestCapture tokenRequestCapture() {
            return new TokenRequestCapture();
        }

        @Bean
        SecurityFilterChain accessSecurity(HttpSecurity http, JdkClientHttpRequestFactory sottoRequests,
                TokenRequestCapture capture) {
            var assertions = new NimbusJwtClientAuthenticationParametersConverter<OAuth2AuthorizationCodeGrantRequest>(
                    registration -> FIXTURE.deploymentKey());
            // Spring Security 7.2.0 defaults to the token endpoint as the audience.
            assertions.setJwtClientAssertionCustomizer(context ->
                    context.getClaims().audience(List.of(FIXTURE.issuer().toString())));
            var tokenClient = new RestClientAuthorizationCodeTokenResponseClient();
            tokenClient.setRestClient(RestClient.builder().requestFactory(sottoRequests)
                    .configureMessageConverters(converters -> {
                        converters.addCustomConverter(new FormHttpMessageConverter());
                        converters.addCustomConverter(new OAuth2AccessTokenResponseHttpMessageConverter());
                    })
                    .defaultStatusHandler(new OAuth2ErrorResponseErrorHandler())
                    .build());
            tokenClient.addParametersConverter(assertions);
            tokenClient.setParametersCustomizer(capture::record);

            return http.authorizeHttpRequests(requests -> requests.anyRequest().authenticated())
                    .oauth2Login(login -> login.tokenEndpoint(token -> token.accessTokenResponseClient(tokenClient))
                            .defaultSuccessUrl("/identity", true)
                            .failureHandler((request, response, failure) -> response.sendError(401)))
                    .build();
        }
    }

    @RestController
    static class IdentityEndpoint {

        @GetMapping("/identity")
        Map<String, String> identity(@AuthenticationPrincipal OidcUser user) {
            return Map.of("issuer", user.getIssuer().toString(), "subject", user.getSubject());
        }
    }

    private record TokenRequest(List<String> audience, String algorithm, String assertionType, String challenge) {
    }

    static class TokenRequestCapture {

        private final AtomicReference<TokenRequest> observed = new AtomicReference<>();

        void record(MultiValueMap<String, String> parameters) {
            // Capture only non-secret values from the final token request form.
            try {
                SignedJWT assertion = SignedJWT.parse(parameters.getFirst("client_assertion"));
                String verifier = parameters.getFirst("code_verifier");
                byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
                observed.set(new TokenRequest(assertion.getJWTClaimsSet().getAudience(),
                        assertion.getHeader().getAlgorithm().getName(), parameters.getFirst("client_assertion_type"),
                        Base64.getUrlEncoder().withoutPadding().encodeToString(digest)));
            }
            catch (ParseException | NoSuchAlgorithmException failure) {
                throw new IllegalStateException("Could not inspect the Spring token request");
            }
        }
    }
}
