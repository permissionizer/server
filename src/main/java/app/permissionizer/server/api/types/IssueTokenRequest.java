package app.permissionizer.server.api.types;

import java.util.List;
import java.util.Map;

public record IssueTokenRequest(
        List<String> targetRepositories,
        Map<String, String> permissions
) {}
