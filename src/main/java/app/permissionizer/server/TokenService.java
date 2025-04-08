package app.permissionizer.server;

import app.permissionizer.server.api.types.IssueTokenRequest;
import app.permissionizer.server.api.types.IssueTokenResponse;
import app.permissionizer.server.github.GithubClient;
import app.permissionizer.server.github.types.AccessTokenRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ResponseStatusException;

import java.lang.invoke.MethodHandles;

@Service
public class TokenService {

    private static final Logger logger = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final GithubClient githubClient;

    public TokenService(GithubClient githubClient) {
        this.githubClient = githubClient;
    }

    public IssueTokenResponse issueScopedToken(
            IssueTokenRequest request,
            String repository,
            String ref,
            String workflowRef,
            String runId
    ) {
        logger.info("Issuing token for target repositories: {}, permissions: {}, from repository: {}, ref: {}, workflowRef: {}, runId: {}", request.targetRepositories(), request.permissions(), repository, ref, workflowRef, runId);
        if (!repository.equals("permissionizer/request-token")) {
            throw new ResponseStatusException(HttpStatus.FORBIDDEN);
        }

        var installation = githubClient.getInstallation(repository);

        // here will be all the policy checking stuff :)

        var accessTokenResponse = githubClient.issueAccessToken(
                installation.id(), new AccessTokenRequest(
                        request.targetRepositories().stream().map(v -> v.split("/")[1]).toList(),
                        request.permissions()
                )
        );

        logger.info("Token for target repositories: {} was issued successfully", request.targetRepositories());

        return new IssueTokenResponse(
                accessTokenResponse.token(),
                accessTokenResponse.expiresAt(),
                accessTokenResponse.permissions(),
                request.targetRepositories(),
                new IssueTokenResponse.IssuedBy(
                        repository,
                        ref,
                        workflowRef,
                        runId
                )
        );
    }
}
