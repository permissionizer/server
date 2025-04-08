package app.permissionizer.server.github.types;

import java.util.List;
import java.util.Map;

public record InstallationResponse(
        long id,
        String clientId,
        Account account,
        String repositorySelection,
        String accessTokensUrl,
        String repositoriesUrl,
        String htmlUrl,
        long appId,
        String appSlug,
        long targetId,
        String targetType,
        Map<String, String> permissions,
        List<String> events,
        String createdAt,
        String updatedAt,
        String singleFileName,
        boolean hasMultipleSingleFiles,
        List<String> singleFilePaths,
        Object suspendedBy,
        Object suspendedAt
) {
    public record Account(
            String login,
            long id,
            String nodeId,
            String avatarUrl,
            String gravatarId,
            String url,
            String htmlUrl,
            String followersUrl,
            String followingUrl,
            String gistsUrl,
            String starredUrl,
            String subscriptionsUrl,
            String organizationsUrl,
            String reposUrl,
            String eventsUrl,
            String receivedEventsUrl,
            String type,
            String userViewType,
            boolean siteAdmin
    ) {}
}
