package app.permissionizer.server;

import app.permissionizer.server.util.Pkcs1KeyParser;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Pattern;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.nio.file.Path;

@ConfigurationProperties("permissionizer")
public record PermissionizerProperties(
        @NotBlank @Pattern(regexp = "^https?::/.*") String githubUrl,
        @NotBlank @Pattern(regexp = "permissionizer-server \\(https?::/.*\\)") String expectedAudience,
        @NotBlank String clientId,
        Path privateKeyPath,
        String privateKey,
        boolean privateKeyFailOnInvalid,
        String webhookSecret
) {
    public PermissionizerProperties {
        if (privateKeyPath != null) {
            Pkcs1KeyParser.parsePem(privateKeyPath);
        } else if (privateKey != null) {
            Pkcs1KeyParser.parsePem(privateKey, "property 'permissionizer.private-key'");
        } else if (privateKeyFailOnInvalid) {
            throw new IllegalArgumentException("Either privateKeyPath or privateKey must be provided");
        }
    }
}
