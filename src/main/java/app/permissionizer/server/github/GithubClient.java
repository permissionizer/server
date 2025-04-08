package app.permissionizer.server.github;

import app.permissionizer.server.PermissionizerProperties;
import app.permissionizer.server.util.Pkcs1KeyParser;
import app.permissionizer.server.github.types.AccessTokenRequest;
import app.permissionizer.server.github.types.AccessTokenResponse;
import app.permissionizer.server.github.types.InstallationResponse;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.aot.hint.annotation.RegisterReflectionForBinding;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.invoke.MethodHandles;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.SignatureException;
import java.util.Base64;
import java.util.Date;

@RegisterReflectionForBinding({ InstallationResponse.class, AccessTokenRequest.class, AccessTokenResponse.class })
@Component
public class GithubClient {
    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final ObjectMapper objectMapper;
    private final PermissionizerProperties properties;
    private final HttpClient httpClient = HttpClient.newBuilder()
            .version(HttpClient.Version.HTTP_2)
            .build();
    private final Base64.Encoder base64 = Base64.getUrlEncoder().withoutPadding();

    public GithubClient(ObjectMapper objectMapper, PermissionizerProperties properties) {
        this.objectMapper = objectMapper;
        this.properties = properties;
    }

    public InstallationResponse getInstallation(String repository) {
        try {
            return httpClient.send(
                    HttpRequest.newBuilder()
                            .GET()
                            .uri(uri("/repos/%s/installation".formatted(repository)))
                            .header("Authorization", "Bearer " + generateJwt())
                            .header("Accept", "application/vnd.github.v3+json")
                            .build(),
                    ofJsonResponse(InstallationResponse.class)
            ).body();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    public AccessTokenResponse issueAccessToken(long installationId, AccessTokenRequest request) {
        try {
            return httpClient.send(
                    HttpRequest.newBuilder()
                            .POST(ofJsonRequest(request))
                            .uri(uri("/app/installations/%s/access_tokens".formatted(installationId)))
                            .header("Authorization", "Bearer " + generateJwt())
                            .header("Accept", "application/vnd.github.v3+json")
                            .build(),
                    ofJsonResponse(AccessTokenResponse.class)
            ).body();
        } catch (IOException | InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    private HttpRequest.BodyPublisher ofJsonRequest(Object body) {
        try {
            return HttpRequest.BodyPublishers.ofString(objectMapper.writeValueAsString(body), StandardCharsets.UTF_8);
        } catch (JsonProcessingException e) {
            throw new UncheckedIOException(e);
        }
    }

    private <T> HttpResponse.BodyHandler<T> ofJsonResponse(Class<T> valueType) {
        return info -> HttpResponse.BodySubscribers.mapping(
                HttpResponse.BodySubscribers.ofInputStream(), is -> {
                    try {
                        return objectMapper.readValue(is, valueType);
                    } catch (IOException e) {
                        throw new UncheckedIOException(e);
                    }
                }
        );
    }

    private URI uri(String path) {
        if (!path.startsWith("/")) {
            path = "/" + path;
        }
        return URI.create(properties.githubUrl() + path);
    }

    private String generateJwt() {
        String clientId = properties.clientId();
        long now = new Date().getTime() / 1000;
        long iat = now - 60;
        long exp = now + 600;

        String header = base64.encodeToString("{\"typ\":\"JWT\",\"alg\":\"RS256\"}".getBytes());
        String payload = base64.encodeToString("{\"iat\":%d,\"exp\":%d,\"iss\":\"%s\"}".formatted(iat, exp, clientId).getBytes());
        String headerPayload = header + "." + payload;
        String signature = sign(headerPayload);
        return headerPayload + "." + signature;
    }

    private String sign(String data) {
        try {
            PrivateKey privateKey = Pkcs1KeyParser.parsePem(properties.privateKeyPath());

            Signature signature = Signature.getInstance("SHA256withRSA");
            signature.initSign(privateKey);
            signature.update(data.getBytes());

            byte[] input = signature.sign();
            return base64.encodeToString(input);
        } catch (NoSuchAlgorithmException | InvalidKeyException | SignatureException e) {
            throw new IllegalStateException("Failed to sign GitHub application JWT", e);
        }
    }
}
