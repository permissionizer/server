package app.permissionizer.server.api.types;

import java.util.List;
import java.util.Map;

public record IssueTokenResponse(
        String token,
        String expiresAt,
        Map<String, String> permissions,
        List<String> repositories,
        IssuedBy issuedBy
) {
    public record IssuedBy(
            String repository,
            String ref,
            String workflowRef,
            String runId
    ) {}
}
