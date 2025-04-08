package app.permissionizer.server.github.types;

import java.util.Map;

public record AccessTokenResponse(
        String token,
        String expiresAt,
        Map<String, String> permissions,
        String repositorySelection
) {}
