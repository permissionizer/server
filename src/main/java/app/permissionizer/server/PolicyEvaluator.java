package app.permissionizer.server;

import app.permissionizer.server.api.types.IssueTokenRequest;
import app.permissionizer.server.github.GithubClientException;
import app.permissionizer.server.util.AllowRequestContainer;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static app.permissionizer.server.util.AllowRequestContainer.withAllowed;

public class PolicyEvaluator {

    public static final int NO_RELEVANT_POLICY = -1;

    private final String POLICY = """
            self: permissionizer/request-token
            allow:
              # (required)
              # Repository requesting the token
              - repository: permissionizer/permissionizer-server
                # (required)
                # Permissions that can be requested by 'permissionizer/permissionizer-server'
                # Only permissions listed here are allowed to be requested, except 'metadata: read', which is added
                # automatically if any other permission is defined.
                # Requestor can always request less permissions or lower access than allowed
                # (e.g. `issues: read` even if `contents: write`, `issues: write` are allowed)
                permissions:
                  contents: read
                  issues: write
                # (optional)
                # Restricts requesting token to specific branches of the requesting repository
                # Uses GitHub format of `ref` (e.g. `refs/heads/main`, `refs/tags/v1.0.0`, `refs/tags/v*`)
                ref: refs/heads/main
                # (optional)
                # Restricts requesting token only from a specific workflow of the requesting repository
                workflow_ref: .github/workflows/release.yaml
            """;

    public PolicyDecision findMatchingPolicy(
            TokenRequestor requestor,
            IssueTokenRequest request) {
        List<PolicyError> errors = new ArrayList<>();
        for (String targetRepository : request.targetRepositories()) {
            try {
                var permissionizerPermissions = fetchPermissionizerPermissions(targetRepository);
                var permissionizerPermissionsDecision = matchPermissions(withAllowed(permissionizerPermissions).request(request.permissions()));
                if (!permissionizerPermissionsDecision.allow()) {
                    errors.add(new PolicyError(
                            targetRepository,
                            NO_RELEVANT_POLICY,
                            ErrorType.permissionizer_no_sufficient_permissions,
                            Map.of("notAllowedPermissions", permissionizerPermissionsDecision.notAllowedPermissions()))
                    );
                }

                RepositoryPolicy repositoryPolicy = fetchRepositoryPolicy(targetRepository);
                if (!repositoryPolicy.self().equals(targetRepository)) {
                    errors.add(new PolicyError(targetRepository, NO_RELEVANT_POLICY, ErrorType.target_repository_misconfigured_self_clause));
                    continue;
                }

                var policyDecision = matchTargetRepositoryPolicy(requestor, request, targetRepository, repositoryPolicy);
                if (!policyDecision.allow()) {
                    errors.addAll(policyDecision.errors());
                }
            } catch (GithubClientException e) {
                if (e.getStatusCode() == 404) {
                    errors.add(new PolicyError(targetRepository, NO_RELEVANT_POLICY, ErrorType.permissionizer_not_installed));
                } else {
                    throw e;
                }
            }
        }

        return new PolicyDecision(errors.isEmpty(), NO_RELEVANT_POLICY, errors);
    }

    private Map<String, String> fetchPermissionizerPermissions(String targetRepository) {
        return Map.of();
    }

    private PolicyDecision matchTargetRepositoryPolicy(TokenRequestor requestor, IssueTokenRequest request, String targetRepository, RepositoryPolicy repositoryPolicy) {
        var policyErrors = new ArrayList<PolicyError>();
        for (int policyIndex = 0; policyIndex < repositoryPolicy.allow().size(); policyIndex++) {
            AllowPolicy allowPolicy = repositoryPolicy.allow().get(policyIndex);
            if (targetRepository.equals(allowPolicy.repository())) {
                if (allowPolicy.ref() != null && !requestor.ref().equals(allowPolicy.ref())) {
                    policyErrors.add(new PolicyError(targetRepository, policyIndex, ErrorType.target_repository_does_not_allow_access_from_ref));
                    continue;
                }
                if (allowPolicy.workflowRef() != null && requestor.workflowRef().equals(allowPolicy.workflowRef())) {
                    policyErrors.add(new PolicyError(targetRepository, policyIndex, ErrorType.target_repository_does_not_allow_access_from_workflow_ref));
                    continue;
                }
                var permissionsDecision = matchPermissions(withAllowed(allowPolicy.permissions()).request(request.permissions()));
                if (!permissionsDecision.allow()) {
                    policyErrors.add(new PolicyError(
                            targetRepository,
                            policyIndex,
                            ErrorType.target_repository_does_not_allow_requested_permission_access,
                            Map.of("notAllowedPermissions", permissionsDecision.notAllowedPermissions()))
                    );

                }
                return new PolicyDecision(true, policyIndex, policyErrors);
            }
        }

        if (policyErrors.isEmpty()) {
            policyErrors.add(new PolicyError(targetRepository, NO_RELEVANT_POLICY, ErrorType.target_repository_does_not_allow_access));
        }
        return new PolicyDecision(false, NO_RELEVANT_POLICY, policyErrors);
    }

    private PermissionsDecision matchPermissions(AllowRequestContainer<Map<String, String>> container) {
        var permissionDecisions = new ArrayList<PermissionDecision>();
        for (Map.Entry<String, String> entry : container.requested().entrySet()) {
            String requestedPermission = entry.getKey();
            String requestedAccess = entry.getValue();
            String allowedAccess = container.allowed().getOrDefault(requestedPermission, "none");
            boolean allow = matchPermission(withAllowed(allowedAccess).request(requestedAccess));
            permissionDecisions.add(new PermissionDecision(allow, requestedPermission, requestedAccess, allowedAccess));
        }
        return new PermissionsDecision(permissionDecisions.stream().allMatch(PermissionDecision::allow), permissionDecisions);
    }

    private boolean matchPermission(AllowRequestContainer<String> container) {
        return switch (container.allowed()) {
            case "read" -> container.requested().equals("read");
            case "write" -> container.requested().equals("read") || container.requested().equals("write");
            case null, default -> false;
        };
    }

    public RepositoryPolicy fetchRepositoryPolicy(String targetRepository) {
        return new RepositoryPolicy();
    }

    public record PermissionsDecision(boolean allow, List<PermissionDecision> permissionDecisions) {
        public String notAllowedPermissions() {
            return permissionDecisions.stream()
                    .filter(decision -> !decision.allow())
                    .map(decision -> "'%s' (requested '%s', allowed: '%s')".formatted(decision.permission(), decision.requestedAccess(), decision.allowedAccess()))
                    .collect(Collectors.joining(", "));
        }
    }
    public record PermissionDecision(boolean allow, String permission, String requestedAccess, String allowedAccess) {
    }

    public record PolicyDecision(boolean allow, int allowPolicyIndex, List<PolicyError> errors) {
    }

    public record PolicyError(String targetRepository, int policyIndex, ErrorType type, Map<String, String> errors) {
        public PolicyError(String targetRepository, int policyIndex, ErrorType type) {
            this(targetRepository, policyIndex, type, Map.of());
        }
        String link() {
            return "https://docs.permissionizer.app/#error-" + type;
        }
    }

    public enum ErrorType {
        permissionizer_not_installed("Permissionizer app does not have access to target repository {targetRepository}. Please reach out to repository owner to install Permissionizer and define policy allowing access."),
        permissionizer_no_sufficient_permissions("Permissionizer app was not granted sufficient sufficient permissions to issue a token with requested permissions: {notAllowedPermissions}"),
        target_repository_misconfigured_self_clause("Target repository {targetRepository} has misconfigured 'self' clause"),
        target_repository_does_not_exists("Target repository {targetRepository} does not exist"),
        target_repository_does_not_allow_access("Target repository {targetRepository} does not allow access to the requesting repository {requestingRepository}"),
        target_repository_does_not_allow_access_from_ref("Target repository {targetRepository} does not allow access to the requesting repository {requestingRepository} from ref {ref}"),
        target_repository_does_not_allow_access_from_workflow_ref("Target repository {targetRepository} does not allow access to the requesting repository {requestingRepository} from workflow_ref {workflow_ref}"),
        target_repository_does_not_allow_all_requested_permissions("Target repository {targetRepository} does not allow one or more requested permissions"),
        target_repository_does_not_allow_requested_permission_access("Target repository {targetRepository} does not allow requested permissions: {notAllowedPermissions}"),
        ;

        private final String message;

        ErrorType(String message) {
            this.message = message;
        }
    }

    public record TokenRequestor(
            String repository,
            String ref,
            String workflowRef,
            String runId) {
    }

    public record RepositoryPolicy(String self, List<AllowPolicy> allow) {
    }

    public record AllowPolicy(
            String repository,
            /*@Nullable */String ref,
            /*@Nullable */String workflowRef,
            Map<String, String> permissions) {
    }
}
